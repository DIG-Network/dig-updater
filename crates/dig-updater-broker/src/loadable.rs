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
//! So this module answers the question WITHOUT running anything: read the artifact's own `DT_NEEDED`
//! set ([`crate::elf`]) and resolve each soname against the host's library set.
//!
//! ## The answer is three-valued, and deliberately asymmetric
//!
//! [`Loadability::Unloadable`] refuses the install; [`Loadability::Loadable`] permits it; and
//! [`Loadability::Indeterminate`] — a non-ELF artifact (`.deb`, `.msi`, `.pkg`), an unparseable image,
//! a host whose library set cannot be enumerated, or any non-Linux host — **permits it too**.
//!
//! That asymmetry is the whole design. Refusing what it cannot prove would be the "safe-looking"
//! choice and is the worse bug: every native-package artifact and every musl host would refuse every
//! component forever, freezing the fleet's updates — including the security updates the beacon exists
//! to deliver. A guard that cannot prove harm must not act. This check can therefore only ever make
//! the beacon do LESS than it already would, never more, and it runs strictly AFTER the signature and
//! digest verification it does not touch.

#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::path::Path;

use crate::elf::{parse_elf_needs, ElfNeeds};

/// Whether the host can load an artifact, and — when it cannot — exactly which sonames are missing so
/// the refusal can NAME them to an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loadability {
    /// Every shared library the image requires is resolvable on this host.
    Loadable,
    /// The image requires shared libraries this host does not provide; it would die in the dynamic
    /// linker before `main`. Carries the missing sonames, in the image's own link order.
    Unloadable {
        /// The `DT_NEEDED` sonames that resolve to nothing on this host.
        missing: Vec<String>,
    },
    /// No answer could be established — and therefore no refusal (see the module doc).
    Indeterminate {
        /// Why no answer was established, in terms an operator can read.
        why: String,
    },
}

/// Decides whether ONE library reference resolves on the host. Called with a bare soname
/// (`libgtk-3.so.0`) for the default search path, and with a `dir/soname` candidate for each entry of
/// the image's own `DT_RUNPATH`. Injected so the DECISION is testable on every OS, independently of
/// whichever libraries the test host happens to carry.
pub type SonameResolver<'a> = dyn Fn(&str) -> bool + 'a;

/// Checks an artifact's loadability at a path — the seam the applier is wired through
/// ([`crate::Installer::loadability`]). Production passes [`host_check`]; tests inject a scripted
/// answer so the refuse / apply branches are both exercised on every runner.
pub type LoadabilityCheck<'a> = dyn Fn(&Path) -> Loadability + 'a;

/// A ceiling on how many bytes of an artifact are read to inspect it. Generous next to any DIG
/// component, and present so a wildly-oversized (or hostile) artifact cannot turn this check into a
/// memory-exhaustion vector inside the privileged pass — the same reason [`crate::elf`] never
/// allocates from a length it read out of the file.
const MAX_INSPECT_BYTES: u64 = 256 * 1024 * 1024;

/// The PURE decision: which of `needs`' required sonames `resolve` cannot find.
///
/// Host-independent by construction — it takes the requirements and a resolver, touches no
/// filesystem, and executes nothing — so the refuse/permit branches are asserted identically on
/// Linux, macOS and Windows.
///
/// A soname counts as resolved if the default search path has it OR any of the image's own
/// `runpath` directories does; `runpath` must already be `$ORIGIN`-expanded by the caller
/// ([`expand_runpath`]), because only the caller knows where the artifact will live.
#[must_use]
pub fn decide_loadability(needs: &ElfNeeds, resolve: &SonameResolver) -> Loadability {
    let missing: Vec<String> = needs
        .needed
        .iter()
        .filter(|soname| !resolves(soname, &needs.runpath, resolve))
        .cloned()
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

/// Inspect the artifact at `path` and decide its loadability under `resolve`.
///
/// Anything that is not a readable, parseable ELF image — a `.deb`/`.msi`/`.pkg`, a corrupt file, an
/// artifact past [`MAX_INSPECT_BYTES`] — is [`Loadability::Indeterminate`], never a refusal (see the
/// module doc). `path` is the broker-private, already digest-verified copy, so the bytes read here are
/// exactly the bytes that would be installed.
#[must_use]
pub fn inspect_artifact(path: &Path, resolve: &SonameResolver) -> Loadability {
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
    decide_loadability(&needs, resolve)
}

/// Read the artifact's bytes, refusing an unreadable or implausibly large file with the reason to
/// report as [`Loadability::Indeterminate`].
fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let size = std::fs::metadata(path)
        .map_err(|e| format!("{} could not be examined: {e}", path.display()))?
        .len();
    if size > MAX_INSPECT_BYTES {
        return Err(format!(
            "{} is {size} bytes, past the {MAX_INSPECT_BYTES}-byte inspection ceiling",
            path.display()
        ));
    }
    std::fs::read(path).map_err(|e| format!("{} could not be read: {e}", path.display()))
}

/// The PRODUCTION loadability check: inspect the artifact against THIS host's library set.
///
/// Every non-Linux host is [`Loadability::Indeterminate`] — the requirement being modelled is the
/// ELF dynamic linker's, and Windows/macOS components install as native packages whose dependency
/// resolution belongs to their own installers.
#[must_use]
pub fn host_check(path: &Path) -> Loadability {
    #[cfg(target_os = "linux")]
    {
        let Some(sonames) = host_sonames() else {
            return Loadability::Indeterminate {
                why: "this host's shared-library set could not be enumerated".to_string(),
            };
        };
        return inspect_artifact(path, &move |candidate: &str| {
            resolves_on_host(candidate, &sonames)
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Loadability::Indeterminate {
            why: "shared-library loadability is only established for ELF hosts".to_string(),
        }
    }
}

/// Whether one candidate resolves on this host: a `dir/soname` candidate (from the image's runpath)
/// must exist as a file; a bare soname must be in the host's library set.
#[cfg(target_os = "linux")]
fn resolves_on_host(candidate: &str, sonames: &HashSet<String>) -> bool {
    if candidate.contains('/') {
        return Path::new(candidate).is_file();
    }
    sonames.contains(candidate)
}

/// Enumerate the sonames this host can load — the linker cache (`ldconfig -p`) when it is available,
/// else the conventional library directories.
///
/// `ldconfig -p` only PRINTS the cache; it neither loads nor executes the artifact, which is the line
/// this module may not cross. `None` means the set could not be established at all, which the caller
/// turns into [`Loadability::Indeterminate`] — never into a refusal.
#[cfg(target_os = "linux")]
#[must_use]
pub fn host_sonames() -> Option<HashSet<String>> {
    let cached = ldconfig_sonames().unwrap_or_default();
    let scanned = scanned_sonames();
    let all: HashSet<String> = cached.union(&scanned).cloned().collect();
    (!all.is_empty()).then_some(all)
}

/// The sonames in the dynamic linker's cache, as `ldconfig -p` reports them. `None` when `ldconfig`
/// is absent or fails (a musl host, a minimal container).
#[cfg(target_os = "linux")]
fn ldconfig_sonames() -> Option<HashSet<String>> {
    let out = std::process::Command::new("ldconfig")
        .arg("-p")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let sonames: HashSet<String> = listing
        .lines()
        // Each cache line is `\t<soname> (<flags>) => <path>`; the leading tab distinguishes an
        // entry from the header line, and the soname is its first whitespace-separated token.
        .filter(|line| line.starts_with('\t'))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect();
    (!sonames.is_empty()).then_some(sonames)
}

/// The sonames present in the conventional library directories — the fallback for a host with no
/// usable `ldconfig` cache.
#[cfg(target_os = "linux")]
fn scanned_sonames() -> HashSet<String> {
    const LIB_DIRS: [&str; 7] = [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
    ];
    LIB_DIRS
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".so"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The requirements of a GTK-linked desktop build — the #1870 artifact's own shape.
    fn gtk_needs() -> ElfNeeds {
        ElfNeeds {
            interp: Some("/lib64/ld-linux-x86-64.so.2".to_string()),
            needed: vec!["libgtk-3.so.0".to_string(), "libc.so.6".to_string()],
            runpath: Vec::new(),
        }
    }

    #[test]
    fn a_missing_soname_makes_the_artifact_unloadable_and_names_it() {
        // dig_ecosystem#1870, at the decision level: a headless host has libc but no GTK. Exactly ONE
        // actor varies — libc stays a truthful control, so an implementation that refused everything
        // (or resolved nothing) could not pass this.
        let headless = |soname: &str| soname != "libgtk-3.so.0";
        assert_eq!(
            decide_loadability(&gtk_needs(), &headless),
            Loadability::Unloadable {
                missing: vec!["libgtk-3.so.0".to_string()]
            },
            "the refusal must NAME the library the host lacks, not merely refuse"
        );
    }

    #[test]
    fn all_sonames_present_is_loadable() {
        let desktop = |_: &str| true;
        assert_eq!(
            decide_loadability(&gtk_needs(), &desktop),
            Loadability::Loadable
        );
    }

    #[test]
    fn no_dt_needed_at_all_is_loadable() {
        // A statically-linked image requires nothing of the loader, so it loads even on a host whose
        // resolver finds NOTHING.
        let barren = |_: &str| false;
        assert_eq!(
            decide_loadability(&ElfNeeds::default(), &barren),
            Loadability::Loadable
        );
    }

    #[test]
    fn a_soname_found_only_via_runpath_is_loadable() {
        // A component that ships its own library beside the binary: the soname is absent system-wide
        // but present in the image's own (already $ORIGIN-expanded) runpath.
        let needs = ElfNeeds {
            interp: None,
            needed: vec!["libdigbundled.so.1".to_string()],
            runpath: vec!["/opt/dig/lib".to_string()],
        };
        let only_in_runpath = |candidate: &str| candidate == "/opt/dig/lib/libdigbundled.so.1";
        assert_eq!(
            decide_loadability(&needs, &only_in_runpath),
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

    #[test]
    fn a_non_elf_artifact_is_indeterminate_not_a_refusal() {
        // The fail-OPEN direction, asserted explicitly: a `.deb` (or an `.msi`, or a corrupt file) is
        // an artifact this check cannot speak about — and refusing it would freeze every
        // native-package component's updates forever.
        let dir = tempfile::tempdir().unwrap();
        let deb = dir.path().join("dig-node.deb");
        std::fs::write(&deb, b"!<arch>\ndebian-binary   2.0\n").unwrap();
        let barren = |_: &str| false;
        assert!(
            matches!(
                inspect_artifact(&deb, &barren),
                Loadability::Indeterminate { .. }
            ),
            "a non-ELF artifact must never be refused"
        );
    }

    #[test]
    fn an_unavailable_host_library_set_is_indeterminate_not_a_refusal() {
        // The same fail-open direction for the OTHER unknown: the host's own library set could not be
        // enumerated (a musl box, a minimal container) — or the host is not an ELF host at all. On
        // every platform, `host_check` over a file whose requirements cannot be established must
        // return Indeterminate rather than a refusal.
        let dir = tempfile::tempdir().unwrap();
        let mystery = dir.path().join("artifact.bin");
        std::fs::write(&mystery, b"\x00\x01\x02\x03not-an-image").unwrap();
        assert!(
            matches!(host_check(&mystery), Loadability::Indeterminate { .. }),
            "an unestablished answer is never a refusal"
        );
    }

    #[test]
    fn a_missing_artifact_is_indeterminate() {
        let barren = |_: &str| false;
        assert!(matches!(
            inspect_artifact(Path::new("/definitely/not/here/1870"), &barren),
            Loadability::Indeterminate { .. }
        ));
    }
}
