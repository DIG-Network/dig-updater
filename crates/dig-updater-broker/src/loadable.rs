//! Can the host actually LOAD the artifact this pass is about to install? (dig_ecosystem#1870)
//!
//! "The bytes hash to the signed digest" and "this binary will run here" are independent facts, and
//! the beacon used to check only the first. The signed manifest offers exactly ONE `linux/x64` build
//! per component; for a desktop-linked component that build names GTK sonames a stock headless server
//! does not carry. Installing it there replaces a WORKING binary with one that dies inside the dynamic
//! linker before `main` — and the pass reported the component as updated, because the download and the
//! digest were both perfect. The re-hash health gate cannot see it either: for a
//! [`ArtifactDigest`](crate::plan::VersionEvidence::ArtifactDigest) component the gate IS a re-hash, so
//! nothing on the path ever establishes that the binary can start.
//!
//! So this module answers the question WITHOUT running anything: read what the artifact's own headers
//! demand of the loader ([`crate::elf`]) and check each demand against the host.
//!
//! Three demands are checked, because all three kill the process before `main` and all three look
//! perfect to a digest:
//!
//! 1. the machine (`e_machine`) — an arm64 build in the `linux/x64` slot dies at `execve` with
//!    `Exec format error`, and every soname it names resolves fine on an x86-64 host;
//! 2. the program interpreter (`PT_INTERP`) — an absent loader dies at `execve` with `ENOENT`,
//!    BEFORE `ld.so` gets to look at a single library;
//! 3. the `DT_NEEDED` sonames — the #1870 failure itself.
//!
//! ## The answer is three-valued, and deliberately asymmetric
//!
//! A refusal ([`Loadability::Unloadable`], [`Loadability::WrongMachine`]) blocks the install;
//! [`Loadability::Loadable`] permits it; and [`Loadability::Indeterminate`] — a non-ELF artifact
//! (`.deb`, `.msi`, `.pkg`), an unparseable image, a host whose library set cannot be established,
//! or any non-Linux host — **permits it too**.
//!
//! That asymmetry is the whole design. Refusing what it cannot prove would be the "safe-looking"
//! choice and is the worse bug: every native-package artifact and every musl host would refuse every
//! component forever, freezing the fleet's updates — including the security updates the beacon exists
//! to deliver, and including the BEACON'S OWN update, which no later fix could reach. A guard that
//! cannot prove harm must not act. This check can therefore only ever make the beacon do LESS than it
//! already would, never more, and it runs strictly AFTER the signature and digest verification it does
//! not touch.
//!
//! The corollary is a rule this module holds carefully: an enumerated host library set is only trusted
//! to REFUSE on when it is demonstrably COMPLETE ([`enumeration_is_complete`]). A set with one stray
//! `.so` in it is not "the host's libraries" — refusing against it would name every real library as
//! missing and freeze the whole fleet, which is precisely the outcome the asymmetry exists to prevent.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::elf::{parse_elf_needs, ElfNeeds};

/// Whether the host can load an artifact, and — when it cannot — exactly what is wrong, so the
/// refusal can NAME it to an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loadability {
    /// Every demand the image makes of the loader is satisfiable on this host.
    Loadable,
    /// The image requires files this host does not provide — shared libraries, or the program
    /// interpreter itself; it would die before `main`. Carries what is missing, in the image's own
    /// order.
    Unloadable {
        /// The requirements that resolve to nothing on this host.
        missing: Vec<String>,
    },
    /// The image is built for another machine, so it cannot start on this host at any library set.
    WrongMachine {
        /// The image's `e_machine`.
        artifact: u16,
        /// This host's `e_machine`.
        host: u16,
    },
    /// No answer could be established — and therefore no refusal (see the module doc).
    Indeterminate {
        /// Why no answer was established, in terms an operator can read.
        why: String,
    },
}

impl Loadability {
    /// Why this artifact was refused, phrased for an operator — `None` when it was not refused.
    #[must_use]
    pub fn refusal(&self) -> Option<String> {
        match self {
            Self::Unloadable { missing } => Some(format!(
                "needs files this host does not provide ({})",
                missing.join(", ")
            )),
            Self::WrongMachine { artifact, host } => Some(format!(
                "is built for machine {artifact}, but this host is machine {host}"
            )),
            Self::Loadable | Self::Indeterminate { .. } => None,
        }
    }
}

/// Decides whether ONE library reference resolves on the host. Called with a bare soname
/// (`libgtk-3.so.0`) for the default search path, and with a `dir/soname` candidate for each entry of
/// the image's own `DT_RUNPATH`. Injected so the DECISION is testable on every OS, independently of
/// whichever libraries the test host happens to carry.
pub type SonameResolver<'a> = dyn Fn(&str) -> bool + 'a;

/// Checks an artifact's loadability at a path — the seam the applier is wired through
/// ([`crate::pass::Installer::loadability`]). Production passes [`host_checker`]'s closure; tests
/// inject a scripted answer so the refuse / apply branches are both exercised on every runner.
pub type LoadabilityCheck<'a> = dyn Fn(&Path) -> Loadability + 'a;

/// Everything about a host that decides whether an image can load on it: which machine it is, and
/// what its filesystem can resolve.
///
/// Bundled into one injectable value so [`decide_loadability`] and [`inspect_artifact`] stay PURE
/// with respect to the host — every branch of the decision is then assertable on a Windows runner,
/// which is what keeps the guard falsifiable rather than hiding behind `#[cfg(unix)]`.
pub struct Host<'a> {
    /// The host's `e_machine`, or `None` to leave the machine unchecked (an architecture this crate
    /// does not name — never a reason to refuse).
    pub machine: Option<u16>,
    /// How one library reference is resolved on this host.
    pub resolve: &'a SonameResolver<'a>,
}

impl<'a> Host<'a> {
    /// A host that resolves references with `resolve` and does not check the machine — the shape a
    /// decision-level test wants when the machine is not what it is asserting.
    #[must_use]
    pub fn resolving_with(resolve: &'a SonameResolver<'a>) -> Self {
        Self {
            machine: None,
            resolve,
        }
    }
}

/// A ceiling on how many bytes of an artifact are read to inspect it. Generous next to any DIG
/// component, and present so a wildly-oversized (or hostile) artifact cannot turn this check into a
/// memory-exhaustion vector inside the privileged pass. The ceiling is only meaningful because
/// [`crate::elf`] separately bounds the WORK done per byte — see its `MAX_NEEDED_ENTRIES`.
const MAX_INSPECT_BYTES: u64 = 256 * 1024 * 1024;

/// The PURE decision: can an image with these requirements load on this host?
///
/// Host-independent by construction — it takes the requirements and a [`Host`], touches no
/// filesystem, and executes nothing — so every refuse/permit branch is asserted identically on
/// Linux, macOS and Windows.
///
/// A soname counts as resolved if the default search path has it OR any of the image's own
/// `runpath` directories does; `runpath` must already be `$ORIGIN`-expanded by the caller
/// ([`expand_runpath`]), because only the caller knows where the artifact will live.
#[must_use]
pub fn decide_loadability(needs: &ElfNeeds, host: &Host) -> Loadability {
    // The machine first: it is decisive regardless of the library set, and an image for another
    // machine never reaches the dynamic linker at all.
    if let Some(host_machine) = host.machine {
        if needs.machine != 0 && needs.machine != host_machine {
            return Loadability::WrongMachine {
                artifact: needs.machine,
                host: host_machine,
            };
        }
    }
    // The interpreter next, and by ABSOLUTE PATH: `ld.so` is what loads the libraries, so if it is
    // absent the process dies at `execve` before any soname is looked at.
    let interp = needs
        .interp
        .iter()
        .filter(|path| !(host.resolve)(path))
        .cloned();
    let missing: Vec<String> = interp
        .chain(
            needs
                .needed
                .iter()
                .filter(|soname| !resolves(soname, &needs.runpath, host.resolve))
                .cloned(),
        )
        .collect();
    if missing.is_empty() {
        Loadability::Loadable
    } else {
        Loadability::Unloadable { missing }
    }
}

/// Whether `soname` resolves via the default search path or any `runpath` directory.
fn resolves(soname: &str, runpath: &[String], resolve: &SonameResolver) -> bool {
    resolve(soname)
        || runpath
            .iter()
            .any(|dir| resolve(&format!("{}/{soname}", dir.trim_end_matches('/'))))
}

/// Expand the `$ORIGIN` in an image's `DT_RUNPATH` to the directory the artifact will be loaded from
/// — the substitution the dynamic linker itself performs, and the reason a component that ships its
/// own libraries beside its binary is loadable even though those sonames are absent system-wide.
#[must_use]
pub fn expand_runpath(runpath: &[String], origin_dir: &Path) -> Vec<String> {
    let origin = origin_dir.to_string_lossy();
    runpath
        .iter()
        .map(|dir| {
            dir.replace("$ORIGIN", &origin)
                .replace("${ORIGIN}", &origin)
        })
        .collect()
}

/// Inspect the artifact at `path` and decide its loadability on `host`.
///
/// Anything that is not a readable, parseable ELF image — a `.deb`/`.msi`/`.pkg`, a corrupt file, an
/// artifact past [`MAX_INSPECT_BYTES`] — is [`Loadability::Indeterminate`], never a refusal (see the
/// module doc). `path` is the broker-private, already digest-verified copy, so the bytes read here are
/// exactly the bytes that would be installed.
#[must_use]
pub fn inspect_artifact(path: &Path, host: &Host) -> Loadability {
    let bytes = match read_bounded(path) {
        Ok(bytes) => bytes,
        Err(why) => return Loadability::Indeterminate { why },
    };
    let mut needs = match parse_elf_needs(&bytes) {
        Ok(needs) => needs,
        Err(e) => {
            return Loadability::Indeterminate {
                why: format!("{} could not be read as an ELF image: {e}", path.display()),
            }
        }
    };
    let origin = path.parent().unwrap_or(Path::new("."));
    needs.runpath = expand_runpath(&needs.runpath, origin);
    decide_loadability(&needs, host)
}

/// Read the artifact's bytes, refusing an unreadable or implausibly large file with the reason to
/// report as [`Loadability::Indeterminate`].
///
/// The read is bounded by the READ ITSELF rather than by a prior `metadata()` check: a file that grows
/// between the two would sail past a ceiling checked in advance, and this path runs on bytes another
/// process staged.
fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let file = std::fs::File::open(path)
        .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
    let mut bytes = Vec::new();
    // One byte past the ceiling, so "is it too big?" is answered by what was actually read.
    file.take(MAX_INSPECT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{} could not be read: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_INSPECT_BYTES {
        return Err(format!(
            "{} is past the {MAX_INSPECT_BYTES}-byte inspection ceiling",
            path.display()
        ));
    }
    Ok(bytes)
}

/// Build the PRODUCTION loadability check for THIS host — the host's library set is enumerated ONCE,
/// here, and every component of the pass is then checked against it.
///
/// Every non-Linux host answers [`Loadability::Indeterminate`] — the requirement being modelled is the
/// ELF dynamic linker's, and Windows/macOS components install as native packages whose dependency
/// resolution belongs to their own installers.
#[must_use]
pub fn host_checker() -> Box<LoadabilityCheck<'static>> {
    #[cfg(target_os = "linux")]
    {
        let enumerated = host_sonames();
        Box::new(move |path: &Path| match &enumerated {
            None => Loadability::Indeterminate {
                why: "this host's shared-library set could not be established".to_string(),
            },
            Some(sonames) => {
                let resolve = |candidate: &str| resolves_with(candidate, sonames, &path_is_file);
                inspect_artifact(
                    path,
                    &Host {
                        machine: HOST_ARCH.machine,
                        resolve: &resolve,
                    },
                )
            }
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(|_path: &Path| Loadability::Indeterminate {
            why: "shared-library loadability is only established for ELF hosts".to_string(),
        })
    }
}

/// Whether one candidate resolves against a host: a `dir/soname` candidate (from the image's runpath)
/// or an absolute interpreter path must EXIST as a file; a bare soname must be in the host's library
/// set.
///
/// `is_file` is injected — not called directly — so the resolution decision is asserted on every OS.
/// A version of this that consulted the filesystem itself would put the runpath branch behind
/// `#[cfg(unix)]`, where a mutation making every path resolve stays green forever.
#[must_use]
pub fn resolves_with(
    candidate: &str,
    sonames: &HashSet<String>,
    is_file: &dyn Fn(&str) -> bool,
) -> bool {
    if candidate.contains('/') {
        return is_file(candidate);
    }
    sonames.contains(candidate)
}

/// Does this path name an existing regular file? The production `is_file` for [`resolves_with`].
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn path_is_file(candidate: &str) -> bool {
    Path::new(candidate).is_file()
}

/// Enumerate the sonames this host can load — the linker cache (`ldconfig -p`) when it is available,
/// unioned with the conventional library directories.
///
/// `ldconfig -p` only PRINTS the cache; it neither loads nor executes the artifact, which is the line
/// this module may not cross. `None` means no set could be ESTABLISHED — either nothing was found, or
/// what was found is not complete enough to refuse against ([`enumeration_is_complete`]) — which the
/// caller turns into [`Loadability::Indeterminate`], never into a refusal.
#[cfg(target_os = "linux")]
#[must_use]
pub fn host_sonames() -> Option<HashSet<String>> {
    let cached = ldconfig_sonames().unwrap_or_default();
    established_set(
        cached,
        &library_dirs_under(Path::new("/"), HOST_ARCH.triplet_prefix),
    )
}

/// The host set, from the linker cache plus a directory scan — the testable core of
/// [`host_sonames`], parameterised by the directories so its completeness rule is asserted on every
/// OS rather than only where `/usr/lib` happens to hold the right libraries.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn established_set(cached: HashSet<String>, dirs: &[PathBuf]) -> Option<HashSet<String>> {
    let mut all = cached;
    all.extend(sonames_in(dirs));
    enumeration_is_complete(&all).then_some(all)
}

/// Is an enumerated soname set complete enough to REFUSE an artifact against?
///
/// The anchor is a C library. Every dynamically-linked ELF artifact the beacon ships needs one, and
/// libc lives in the same directory as the rest of the system's libraries — so a set WITHOUT one was
/// not "scanned and found wanting", it was scanned in the wrong place (a multiarch triplet this crate
/// did not look in) or barely scanned at all.
///
/// This is the difference between a fail-open safeguard and a fleet-wide freeze. Requiring merely
/// "non-empty" lets ONE stray `.so` anywhere count as the host's library set, after which a real
/// glibc artifact is refused for missing `libc.so.6` — every component, on every pass, including the
/// beacon's own update, which nothing shipped through the beacon could then repair.
#[must_use]
pub fn enumeration_is_complete(sonames: &HashSet<String>) -> bool {
    sonames.iter().any(|name| looks_like_libc(name))
}

/// Whether a file name is a C library under any of the names the supported libcs use.
fn looks_like_libc(name: &str) -> bool {
    ["libc.so", "libc-", "libc.musl", "ld-musl"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// The sonames present in `dirs`.
#[must_use]
pub fn sonames_in(dirs: &[PathBuf]) -> HashSet<String> {
    dirs.iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".so"))
        .collect()
}

/// The library directories to scan under `root`, for a host whose architecture is `arch_token`.
///
/// The multiarch directories are DERIVED from what is on the filesystem rather than hardcoded: a
/// fixed `x86_64-linux-gnu` made every library on a Debian arm64 host — a supported platform —
/// invisible, which under a "non-empty is enough" completeness rule turned into refusing every
/// component. Only triplets matching this host's architecture are scanned: an x86-64 host must not
/// count the i386 flavour of a soname as resolvable, because its 64-bit loader will not accept it.
#[must_use]
pub fn library_dirs_under(root: &Path, arch_token: Option<&str>) -> Vec<PathBuf> {
    const BASE_DIRS: [&str; 5] = ["lib", "lib64", "usr/lib", "usr/lib64", "usr/local/lib"];
    let base: Vec<PathBuf> = BASE_DIRS.iter().map(|dir| root.join(dir)).collect();
    let multiarch = base
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| is_multiarch_dir_for(&entry.file_name().to_string_lossy(), arch_token))
        .map(|entry| entry.path());
    base.iter().cloned().chain(multiarch).collect()
}

/// Whether a directory name is a multiarch triplet (`aarch64-linux-gnu`, `x86_64-linux-musl`) for
/// `arch_token`. With no known architecture token nothing is claimed and no triplet is scanned —
/// counting another architecture's libraries would produce a FALSE `Loadable`, the one direction this
/// module must never be wrong in.
fn is_multiarch_dir_for(name: &str, arch_token: Option<&str>) -> bool {
    let Some(arch) = arch_token else {
        return false;
    };
    name.contains("-linux-") && name.starts_with(arch)
}

/// The sonames in the dynamic linker's cache, as `ldconfig -p` reports them. `None` when `ldconfig`
/// is absent, hangs, or fails (a musl host, a minimal container) — in which case the directory scan
/// stands alone, so nothing here is load-bearing for correctness.
#[cfg(target_os = "linux")]
fn ldconfig_sonames() -> Option<HashSet<String>> {
    let listing = ldconfig_listing(&crate::install::first_trusted(&LDCONFIG_CANDIDATES).ok()?)?;
    let sonames: HashSet<String> = listing
        .lines()
        .filter_map(|line| cache_entry_soname(line, HOST_ARCH.ldconfig_abi))
        .map(str::to_string)
        .collect();
    (!sonames.is_empty()).then_some(sonames)
}

/// The absolute paths `ldconfig` is looked for at, in order.
///
/// Never a bare `ldconfig` resolved through `PATH`. The Linux beacon is a root systemd unit whose unit
/// file sets no `Environment=PATH=`, so it inherits systemd's default beginning
/// `/usr/local/sbin:/usr/local/bin:` — both of which PRECEDE `ldconfig`'s real home. An unprivileged
/// user able to write either of those directories would otherwise have their `ldconfig` executed as
/// root on the next daily pass. This is the same "never a bare name resolved through `PATH`"
/// discipline [`crate::install::first_trusted`] already applies to `dpkg`/`msiexec`/`systemctl`.
pub const LDCONFIG_CANDIDATES: [&str; 4] = [
    "/usr/sbin/ldconfig",
    "/sbin/ldconfig",
    "/usr/bin/ldconfig",
    "/bin/ldconfig",
];

/// How long `ldconfig` is given to print the cache before it is killed. A planted or wedged
/// `ldconfig` must not stall the pass, which holds the single-instance lock while it runs.
#[cfg(target_os = "linux")]
const LDCONFIG_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// A ceiling on how much of `ldconfig`'s output is buffered. `Command::output()` buffers without
/// limit; a program that prints forever would otherwise exhaust a root process's memory.
#[cfg(target_os = "linux")]
const LDCONFIG_OUTPUT_CAP: u64 = 4 * 1024 * 1024;

/// Run `ldconfig -p` at an absolute, verified path with a cleared environment, a byte cap and a
/// deadline, returning its listing. `None` on any failure — the caller treats that as "no cache".
#[cfg(target_os = "linux")]
fn ldconfig_listing(program: &Path) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(program)
        .arg("-p")
        // The environment of a privileged parent is an input to someone else's code — the same
        // posture `crate::probe` takes for the one other program this crate spawns.
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    // Read on a side thread so the DEADLINE is real: a child that never writes and never exits would
    // otherwise block this read forever. The handle is deliberately dropped rather than joined on the
    // timeout path — the reader is bounded by the cap and must not be able to hold up the pass.
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout
            .by_ref()
            .take(LDCONFIG_OUTPUT_CAP)
            .read_to_end(&mut buf);
        buf
    });
    let exited = crate::probe::wait_within(&mut child, LDCONFIG_BUDGET);
    if exited != Some(true) {
        crate::probe::kill_and_reap(&mut child);
        return None;
    }
    let bytes = reader.join().ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The soname of one `ldconfig -p` cache line, if the entry is usable on a host whose ABI flag is
/// `host_abi`.
///
/// Each entry reads `\t<soname> (<flags>) => <path>`; the leading tab distinguishes an entry from the
/// header line. The FLAGS matter: on a multiarch host the same soname appears once per ABI
/// (`(libc6)` for i386, `(libc6,x86-64)` for amd64), so ignoring them lets the 32-bit-only flavour of
/// a library count as resolvable while the 64-bit loader refuses it — a false `Loadable`, which is the
/// one direction this module must never be wrong in.
///
/// Flags this function does not recognise (`(ELF)`, or none at all) are ACCEPTED: an unrecognised tag
/// is not evidence of a mismatch, and refusing on it would drop real libraries from the host set.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn cache_entry_soname<'a>(line: &'a str, host_abi: Option<&str>) -> Option<&'a str> {
    let entry = line.strip_prefix('\t')?;
    let soname = entry.split_whitespace().next()?;
    let flags = entry
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(flags, _)| flags);
    match (flags, host_abi) {
        // A libc-tagged entry names its ABI, so this host's tag has to be among them.
        (Some(flags), Some(abi)) if flags.contains("libc") && !flags.contains(abi) => None,
        _ => Some(soname),
    }
}

/// The three facts about a host's ARCHITECTURE that this check needs: which machine an image must be
/// built for, which multiarch triplet directory holds its libraries, and which ABI flag `ldconfig -p`
/// tags them with.
///
/// One value per architecture, rather than three independently `#[cfg]`-ed constants, because they
/// have to AGREE: a host that claims `x86_64` libraries while accepting `AArch64` images would produce
/// a false `Loadable`, and keeping them in one literal makes disagreeing impossible to do by accident.
/// `None` in any field means "this crate cannot name it", which never causes a refusal.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct HostArch {
    /// The `e_machine` an image must name to run here.
    machine: Option<u16>,
    /// The prefix of this host's multiarch triplet directories (`x86_64-linux-gnu`'s `x86_64`).
    triplet_prefix: Option<&'static str>,
    /// The ABI flag `ldconfig -p` tags this host's libraries with (`(libc6,x86-64)`'s `x86-64`).
    ldconfig_abi: Option<&'static str>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(target_arch = "x86_64")]
const HOST_ARCH: HostArch = HostArch {
    machine: Some(crate::elf::EM_X86_64),
    triplet_prefix: Some("x86_64"),
    ldconfig_abi: Some("x86-64"),
};

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(target_arch = "aarch64")]
const HOST_ARCH: HostArch = HostArch {
    machine: Some(crate::elf::EM_AARCH64),
    triplet_prefix: Some("aarch64"),
    ldconfig_abi: Some("AArch64"),
};

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(target_arch = "x86")]
const HOST_ARCH: HostArch = HostArch {
    machine: Some(crate::elf::EM_386),
    triplet_prefix: Some("i386"),
    // 32-bit x86 entries carry no ABI flag of their own (`(libc6)`), so nothing is excluded.
    ldconfig_abi: None,
};

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(target_arch = "arm")]
const HOST_ARCH: HostArch = HostArch {
    machine: Some(crate::elf::EM_ARM),
    triplet_prefix: Some("arm"),
    // `(libc6,soft-float)` / `(libc6,hard-float)` — two possibilities, so neither is required.
    ldconfig_abi: None,
};

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(target_arch = "riscv64")]
const HOST_ARCH: HostArch = HostArch {
    machine: Some(crate::elf::EM_RISCV),
    triplet_prefix: Some("riscv64"),
    ldconfig_abi: None,
};

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "riscv64"
)))]
/// An architecture this crate does not name checks nothing and claims nothing.
const HOST_ARCH: HostArch = HostArch {
    machine: None,
    triplet_prefix: None,
    ldconfig_abi: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::fixture::{synth_elf, synth_elf_for};
    use crate::elf::{EM_AARCH64, EM_X86_64};

    /// The requirements of a GTK-linked desktop build — the #1870 artifact's own shape.
    fn gtk_needs() -> ElfNeeds {
        ElfNeeds {
            machine: EM_X86_64,
            interp: Some("/lib64/ld-linux-x86-64.so.2".to_string()),
            needed: vec!["libgtk-3.so.0".to_string(), "libc.so.6".to_string()],
            runpath: Vec::new(),
        }
    }

    /// A host that resolves whatever `resolve` says and is the same machine as the fixture, so a
    /// soname assertion is not silently answered by the machine check.
    fn headless_x86_64<'a>(resolve: &'a SonameResolver<'a>) -> Host<'a> {
        Host {
            machine: Some(EM_X86_64),
            resolve,
        }
    }

    #[test]
    fn a_missing_soname_makes_the_artifact_unloadable_and_names_it() {
        // dig_ecosystem#1870, at the decision level: a headless host has libc and the loader but no
        // GTK. Exactly ONE actor varies — libc and the interpreter stay truthful controls, so an
        // implementation that refused everything (or resolved nothing) could not pass this.
        let headless = |name: &str| name != "libgtk-3.so.0";
        assert_eq!(
            decide_loadability(&gtk_needs(), &headless_x86_64(&headless)),
            Loadability::Unloadable {
                missing: vec!["libgtk-3.so.0".to_string()]
            },
            "the refusal must NAME the library the host lacks, not merely refuse"
        );
    }

    #[test]
    fn all_requirements_present_is_loadable() {
        let desktop = |_: &str| true;
        assert_eq!(
            decide_loadability(&gtk_needs(), &headless_x86_64(&desktop)),
            Loadability::Loadable
        );
    }

    #[test]
    fn an_absent_program_interpreter_is_a_refusal_naming_the_loader() {
        // The failure mode that beats every soname check: `execve` fails with ENOENT before `ld.so`
        // runs, so the process dies without a single library being looked up. Only the INTERPRETER
        // varies here — every soname resolves — so a decision that ignored PT_INTERP returns
        // `Loadable` and fails this.
        let no_loader = |name: &str| name != "/lib64/ld-linux-x86-64.so.2";
        assert_eq!(
            decide_loadability(&gtk_needs(), &headless_x86_64(&no_loader)),
            Loadability::Unloadable {
                missing: vec!["/lib64/ld-linux-x86-64.so.2".to_string()]
            },
            "an image whose loader is absent cannot start, whatever its libraries resolve to"
        );
    }

    #[test]
    fn an_image_for_another_machine_is_refused_even_though_every_soname_resolves() {
        // An arm64 build dropped into the `linux/x64` slot: `libc.so.6` and `libgcc_s.so.1` resolve
        // perfectly on an x86-64 host, so the soname check alone calls it loadable and the pass
        // installs a binary that dies with `Exec format error`.
        let everything_resolves = |_: &str| true;
        let needs = ElfNeeds {
            machine: EM_AARCH64,
            needed: vec!["libc.so.6".to_string(), "libgcc_s.so.1".to_string()],
            ..ElfNeeds::default()
        };
        assert_eq!(
            decide_loadability(&needs, &headless_x86_64(&everything_resolves)),
            Loadability::WrongMachine {
                artifact: EM_AARCH64,
                host: EM_X86_64
            }
        );
        // The truthful control: the SAME requirements for the host's own machine are loadable, so the
        // check cannot be passing by refusing everything.
        assert_eq!(
            decide_loadability(
                &ElfNeeds {
                    machine: EM_X86_64,
                    ..needs
                },
                &headless_x86_64(&everything_resolves)
            ),
            Loadability::Loadable
        );
    }

    #[test]
    fn an_unnamed_host_machine_never_refuses_on_the_machine() {
        // An architecture this crate does not name is not evidence of a mismatch (the module's
        // asymmetry): the machine goes unchecked rather than refusing every artifact.
        let everything_resolves = |_: &str| true;
        let needs = ElfNeeds {
            machine: EM_AARCH64,
            ..ElfNeeds::default()
        };
        assert_eq!(
            decide_loadability(&needs, &Host::resolving_with(&everything_resolves)),
            Loadability::Loadable
        );
    }

    #[test]
    fn no_dt_needed_at_all_is_loadable() {
        // A statically-linked image requires nothing of the loader, so it loads even on a host whose
        // resolver finds NOTHING.
        let barren = |_: &str| false;
        assert_eq!(
            decide_loadability(&ElfNeeds::default(), &Host::resolving_with(&barren)),
            Loadability::Loadable
        );
    }

    #[test]
    fn a_soname_found_only_via_runpath_is_loadable() {
        // A component that ships its own library beside the binary: the soname is absent system-wide
        // but present in the image's own (already $ORIGIN-expanded) runpath.
        let needs = ElfNeeds {
            needed: vec!["libdigbundled.so.1".to_string()],
            runpath: vec!["/opt/dig/lib".to_string()],
            ..ElfNeeds::default()
        };
        let only_in_runpath = |candidate: &str| candidate == "/opt/dig/lib/libdigbundled.so.1";
        assert_eq!(
            decide_loadability(&needs, &Host::resolving_with(&only_in_runpath)),
            Loadability::Loadable
        );
    }

    #[test]
    fn origin_in_a_runpath_expands_to_the_artifacts_own_directory() {
        let expanded = expand_runpath(
            &["$ORIGIN/../lib".to_string(), "/opt/dig/lib".to_string()],
            Path::new("/opt/dig/bin"),
        );
        assert_eq!(expanded, vec!["/opt/dig/bin/../lib", "/opt/dig/lib"]);
    }

    // --- the PRODUCTION byte path, end to end, over a real ELF file on disk ---

    /// Write `bytes` as an artifact file and return the directory holding it (kept alive by the
    /// caller) plus its path.
    fn artifact(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dig-app");
        std::fs::write(&path, bytes).expect("write the artifact");
        (dir, path)
    }

    #[test]
    fn inspect_artifact_refuses_a_real_gtk_linked_elf_on_a_headless_host() {
        // THE dig_ecosystem#1870 acceptance test, and the only one that runs the whole production
        // byte path in a DECISIVE direction: a real ELF image on disk, read by `read_bounded`, parsed
        // by `parse_elf_needs`, decided by `decide_loadability`. Neuter any link in that chain — cap
        // the read at zero bytes, make the parse bail, drop the DT_NEEDED walk — and this test is
        // what dies.
        let (_dir, path) = artifact(&synth_elf(
            &["libgtk-3.so.0", "libc.so.6"],
            None,
            Some("/lib64/ld-linux-x86-64.so.2"),
        ));
        let headless = |name: &str| name != "libgtk-3.so.0";
        assert_eq!(
            inspect_artifact(&path, &headless_x86_64(&headless)),
            Loadability::Unloadable {
                missing: vec!["libgtk-3.so.0".to_string()]
            },
            "the real artifact's own DT_NEEDED set must reach the decision"
        );
    }

    #[test]
    fn inspect_artifact_permits_a_real_elf_whose_libraries_are_all_present() {
        // The other decisive direction over the same production path: without this, an implementation
        // that returned `Unloadable` for every ELF would pass the refusal test above.
        let (_dir, path) = artifact(&synth_elf(
            &["libgtk-3.so.0", "libc.so.6"],
            None,
            Some("/lib64/ld-linux-x86-64.so.2"),
        ));
        let desktop = |_: &str| true;
        assert_eq!(
            inspect_artifact(&path, &headless_x86_64(&desktop)),
            Loadability::Loadable
        );
    }

    #[test]
    fn inspect_artifact_reads_the_real_machine_out_of_the_file() {
        // The arm64-in-the-x64-slot artifact, through the production path rather than a hand-built
        // `ElfNeeds`.
        let (_dir, path) = artifact(&synth_elf_for(EM_AARCH64, &["libc.so.6"], None, None));
        let everything_resolves = |_: &str| true;
        assert_eq!(
            inspect_artifact(&path, &headless_x86_64(&everything_resolves)),
            Loadability::WrongMachine {
                artifact: EM_AARCH64,
                host: EM_X86_64
            }
        );
    }

    #[test]
    fn a_real_elf_finds_its_bundled_library_through_its_own_runpath() {
        // `$ORIGIN` expansion against the artifact's ACTUAL directory, which only the production path
        // knows — the decision-level test above has to be handed the expanded value.
        let (dir, path) = artifact(&synth_elf(
            &["libdigbundled.so.1"],
            Some("$ORIGIN/lib"),
            None,
        ));
        // The candidate is composed by `resolves` as `{runpath}/{soname}` — a `/` separator on every
        // OS, because it is an ELF search path and not a host path.
        let bundled = format!("{}/lib/libdigbundled.so.1", dir.path().display());
        let bundled_only = |candidate: &str| candidate == bundled;
        assert_eq!(
            inspect_artifact(&path, &headless_x86_64(&bundled_only)),
            Loadability::Loadable
        );
    }

    #[test]
    fn a_non_elf_artifact_is_indeterminate_not_a_refusal() {
        // The fail-OPEN direction, asserted explicitly: a `.deb` (or an `.msi`, or a corrupt file) is
        // an artifact this check cannot speak about — and refusing it would freeze every
        // native-package component's updates forever.
        let (_dir, path) = artifact(b"!<arch>\ndebian-binary   2.0\n");
        let barren = |_: &str| false;
        assert!(
            matches!(
                inspect_artifact(&path, &Host::resolving_with(&barren)),
                Loadability::Indeterminate { .. }
            ),
            "a non-ELF artifact must never be refused"
        );
    }

    #[test]
    fn an_unavailable_host_library_set_is_indeterminate_not_a_refusal() {
        // The same fail-open direction for the OTHER unknown: the host's own library set could not be
        // established (a musl box, a minimal container) — or the host is not an ELF host at all. On
        // every platform, the production checker over a file whose requirements cannot be established
        // must return Indeterminate rather than a refusal.
        let (_dir, path) = artifact(b"\x00\x01\x02\x03not-an-image");
        assert!(
            matches!(host_checker()(&path), Loadability::Indeterminate { .. }),
            "an unestablished answer is never a refusal"
        );
    }

    #[test]
    fn a_missing_artifact_is_indeterminate() {
        let barren = |_: &str| false;
        assert!(matches!(
            inspect_artifact(
                Path::new("/definitely/not/here/1870"),
                &Host::resolving_with(&barren)
            ),
            Loadability::Indeterminate { .. }
        ));
    }

    // --- the host-set half: resolution, completeness, directories, the cache parse ---

    #[test]
    fn a_bare_soname_resolves_only_through_the_host_set_and_a_path_only_through_the_filesystem() {
        // The `resolves_with` decision, on every OS. The mutation this catches is the one that made
        // the filesystem predicate answer `true` unconditionally: with `never` below, a soname absent
        // from the host set must NOT become resolvable merely because the image carries a runpath.
        let host: HashSet<String> = ["libc.so.6".to_string()].into_iter().collect();
        let never = |_: &str| false;
        assert!(resolves_with("libc.so.6", &host, &never), "in the host set");
        assert!(
            !resolves_with("libgtk-3.so.0", &host, &never),
            "absent from the host set and unreachable on the filesystem"
        );
        assert!(
            !resolves_with("/opt/dig/lib/libc.so.6", &host, &never),
            "a PATH candidate must be answered by the filesystem, never by the soname set"
        );
        let only_bundled = |candidate: &str| candidate == "/opt/dig/lib/libgtk-3.so.0";
        assert!(resolves_with(
            "/opt/dig/lib/libgtk-3.so.0",
            &host,
            &only_bundled
        ));
        assert!(
            !resolves_with("libgtk-3.so.0", &host, &only_bundled),
            "a bare soname must not be probed as a relative filesystem path"
        );
    }

    #[test]
    fn an_enumerated_set_without_a_libc_is_not_complete_enough_to_refuse_against() {
        // BLOCKING: "non-empty" is not "enumerated". One stray `.so` used to count as the host's
        // library set, after which a real glibc artifact was refused for missing `libc.so.6` —
        // every component, every pass, including the beacon's own update.
        let stray: HashSet<String> = ["libfoo.so".to_string()].into_iter().collect();
        assert!(
            !enumeration_is_complete(&stray),
            "a set with no C library in it was scanned in the wrong place, not found wanting"
        );
        assert!(!enumeration_is_complete(&HashSet::new()));
        for libc in ["libc.so.6", "libc-2.36.so", "ld-musl-x86_64.so.1"] {
            let mut set = stray.clone();
            set.insert(libc.to_string());
            assert!(
                enumeration_is_complete(&set),
                "{libc} anchors the enumeration, so refusals against this set are honest"
            );
        }
    }

    #[test]
    fn the_host_set_is_none_until_the_enumeration_is_anchored() {
        // The same rule at the seam `host_sonames` uses, over a real (fabricated) filesystem: an
        // arm64-shaped tree yields a set only once its libc is actually visible.
        let root = tempfile::tempdir().expect("tempdir");
        let multiarch = root.path().join("usr/lib/aarch64-linux-gnu");
        std::fs::create_dir_all(&multiarch).expect("create the multiarch dir");
        std::fs::write(root.path().join("usr/lib").join("libstray.so"), b"x").expect("stray");

        let dirs = library_dirs_under(root.path(), Some("aarch64"));
        assert_eq!(
            established_set(HashSet::new(), &dirs),
            None,
            "a lone stray .so must not be trusted as this host's library set"
        );

        std::fs::write(multiarch.join("libc.so.6"), b"x").expect("libc");
        let dirs = library_dirs_under(root.path(), Some("aarch64"));
        let set = established_set(HashSet::new(), &dirs)
            .expect("an anchored enumeration establishes a set");
        assert!(
            set.contains("libc.so.6") && set.contains("libstray.so"),
            "the derived multiarch directory must be scanned: {set:?}"
        );
    }

    #[test]
    fn multiarch_directories_are_derived_and_scoped_to_this_hosts_architecture() {
        // The hardcoded `x86_64-linux-gnu` made every library on a Debian arm64 host invisible; and
        // counting ANOTHER architecture's triplet would be worse still — a false `Loadable`.
        for (arch, wanted, unwanted) in [
            ("aarch64", "aarch64-linux-gnu", "x86_64-linux-gnu"),
            ("x86_64", "x86_64-linux-musl", "i386-linux-gnu"),
        ] {
            assert!(is_multiarch_dir_for(wanted, Some(arch)));
            assert!(
                !is_multiarch_dir_for(unwanted, Some(arch)),
                "{unwanted} is not loadable on a {arch} host"
            );
        }
        assert!(
            !is_multiarch_dir_for("x86_64-linux-gnu", None),
            "with no architecture named, no triplet may be claimed"
        );
        assert!(!is_multiarch_dir_for("systemd", Some("x86_64")));
    }

    #[test]
    fn ldconfig_is_only_ever_looked_for_at_an_absolute_trusted_path() {
        // The beacon is a root systemd unit inheriting a PATH that begins /usr/local/sbin, so a bare
        // name here is a root code-execution vector for anyone who can write that directory.
        for candidate in LDCONFIG_CANDIDATES {
            // Asserted as a POSIX absolute path, not via `Path::is_absolute` — that answers for the
            // TEST host, and on a Windows runner it would call every one of these relative and turn
            // the assertion into its own opposite.
            assert!(
                candidate.starts_with('/'),
                "{candidate} would be resolved through PATH"
            );
        }
        assert!(
            LDCONFIG_CANDIDATES.contains(&"/usr/sbin/ldconfig"),
            "ldconfig's real home must be among the candidates or the cache is never read"
        );
    }

    #[test]
    fn a_cache_entry_for_another_abi_is_not_counted_as_resolvable() {
        // A multiarch host lists the same soname once per ABI. Taking the soname without its flags
        // let the i386 flavour satisfy a 64-bit image — a false `Loadable`.
        assert_eq!(
            cache_entry_soname(
                "\tlibz.so.1 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libz.so.1",
                Some("x86-64")
            ),
            Some("libz.so.1")
        );
        assert_eq!(
            cache_entry_soname(
                "\tlibz.so.1 (libc6) => /usr/lib/i386-linux-gnu/libz.so.1",
                Some("x86-64")
            ),
            None,
            "the 32-bit flavour is not loadable by a 64-bit image"
        );
        assert_eq!(
            cache_entry_soname(
                "\tlibz.so.1 (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/libz.so.1",
                Some("AArch64")
            ),
            Some("libz.so.1")
        );
    }

    #[test]
    fn an_unrecognised_cache_line_is_accepted_or_skipped_rather_than_misread() {
        // Fail-open on the flags this function cannot interpret: dropping a real library from the
        // host set would refuse artifacts that load perfectly well.
        assert_eq!(
            cache_entry_soname(
                "\tlibodd.so.1 (ELF) => /usr/lib/libodd.so.1",
                Some("x86-64")
            ),
            Some("libodd.so.1"),
            "an unrecognised ABI tag is not evidence of a mismatch"
        );
        assert_eq!(
            cache_entry_soname("\tlibz.so.1 (libc6) => /x/libz.so.1", None),
            Some("libz.so.1"),
            "with no host ABI named, nothing is excluded"
        );
        assert_eq!(
            cache_entry_soname(
                "1234 libs found in cache `/etc/ld.so.cache'",
                Some("x86-64")
            ),
            None,
            "the header line is not an entry"
        );
    }

    #[test]
    fn sonames_in_reads_only_shared_libraries() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in ["libc.so.6", "libz.so", "README", "ldconfig"] {
            std::fs::write(dir.path().join(name), b"x").expect("write");
        }
        let found = sonames_in(&[dir.path().to_path_buf()]);
        assert_eq!(
            found,
            ["libc.so.6".to_string(), "libz.so".to_string()]
                .into_iter()
                .collect::<HashSet<String>>()
        );
    }

    #[test]
    fn a_refusal_describes_itself_and_a_permission_does_not() {
        assert!(Loadability::Loadable.refusal().is_none());
        assert!(Loadability::Indeterminate { why: "x".into() }
            .refusal()
            .is_none());
        assert!(Loadability::Unloadable {
            missing: vec!["libgtk-3.so.0".to_string()]
        }
        .refusal()
        .expect("a refusal explains itself")
        .contains("libgtk-3.so.0"));
        let machine = Loadability::WrongMachine {
            artifact: EM_AARCH64,
            host: EM_X86_64,
        }
        .refusal()
        .expect("a refusal explains itself");
        assert!(
            machine.contains("183") && machine.contains("62"),
            "{machine}"
        );
    }
}
