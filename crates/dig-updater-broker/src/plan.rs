//! Enumerating what is installed and PLANNING what to do about it.
//!
//! Given the RE-VERIFIED manifest (the authority — SPEC §9) and the artifacts the worker staged,
//! the broker decides, per tracked component, whether this pass should **Install** (nothing there
//! yet), **Update** (an older or unreadable build is present), or **Skip** (already current). It
//! does NOT re-implement that matrix: it detects the installed version and calls
//! [`dig_release_resolver`]'s shared [`decide`], the exact same logic `dig-installer` ships, so a
//! DIG box makes one consistent decision no matter which tool asks (SPEC §12, CLAUDE.md §4.1).
//!
//! A [`Catalog`] maps each tracked component to WHERE it installs and HOW ([`InstallMethod`]) on
//! this host. The alpha defaults ([`Catalog::alpha_defaults`]) cover dig-node (native package),
//! digstore / dig-updater / dig-dns (raw binary); they are fully overridable so tests and the
//! installer (#504-H) can point at their own destinations.

use std::path::{Path, PathBuf};

use dig_release_resolver::{decide, DetectedVersion, UpdateAction};

use dig_updater_trust::Manifest;
use dig_updater_worker::{Platform, StagedArtifact};

use crate::error::BrokerError;

/// The manifest component name the beacon tracks for ITSELF. The applier uses this to carve its
/// own component out of the ordinary per-component loop and apply it LAST, via a platform-specific
/// self-swap instead of the generic per-OS installer (SPEC §8.1, #504-F).
pub const BEACON_COMPONENT_NAME: &str = "dig-updater";

/// The manifest component name of the per-user identity agent (SPEC §9.7) — the one tracked
/// component that is a desktop tray daemon rather than a CLI or an OS service, and so the one that
/// requires [`VersionEvidence::Required`].
pub const DIG_APP_COMPONENT_NAME: &str = "dig-app";

/// The radix that keeps a packed `build` number monotonic in the version — the SAME encoding the
/// feed-signer uses (SPEC §10.3: `major·10⁶ + minor·10³ + patch`), so the broker's anti-downgrade
/// comparison agrees byte-for-byte with the number the signed manifest carries.
const FIELD_RADIX: u64 = 1_000;

/// Pack an installed component's `--version` string into its monotonic `build` number — on the
/// SAME per-channel scale the signed manifest's `build`/floor use (SPEC §10.3, §7.5, #591 D5).
///
/// The version string is SELF-DESCRIBING, so no channel argument is needed:
///
/// - a **nightly** prerelease `X.Y.Z-nightly.YYYYMMDD.<sha>` packs to its UTC build DATE `YYYYMMDD`
///   ([`nightly_build_date`]) — the nightly scale, matching the feed-signer's `parse_nightly_build`.
///   The nightly `-suffix` is NEVER semver-parsed into the anti-downgrade decision (#591 D5): doing
///   so would pack it onto the stable thousands-scale and mis-compare it against a YYYYMMDD floor.
/// - a **stable** `major.minor.patch` (v-prefix + `+build` metadata tolerated) packs to the packed
///   monotonic semver, mirroring the feed-signer's `Version::build_number`.
///
/// Returns `None` for anything it cannot age — a malformed nightly date, or a non-semver stable
/// string — which the caller treats as "cannot prove its age", the conservative default on the
/// rollback-floor check. The two scales are never compared across channels: each channel keeps its
/// own monotonic trust state (§6, `state.rs`), so a stable build (thousands) and a nightly build
/// (tens of millions) never meet.
#[must_use]
pub fn pack_build(version: &str) -> Option<u64> {
    // A nightly-shaped version is aged by its date, never by its semver core — even when the date
    // is malformed (in which case it is un-ageable, NOT silently semver-packed onto the wrong scale).
    if version.contains("-nightly.") {
        return nightly_build_date(version);
    }
    let trimmed = version.trim().strip_prefix('v').unwrap_or(version.trim());
    let core = trimmed.split(['-', '+']).next().unwrap_or(trimmed);
    let mut parts = core.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    let patch: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || minor >= FIELD_RADIX || patch >= FIELD_RADIX {
        return None;
    }
    Some(major * FIELD_RADIX * FIELD_RADIX + minor * FIELD_RADIX + patch)
}

/// The nightly build number: the UTC build DATE `YYYYMMDD` parsed from a nightly prerelease version
/// `X.Y.Z-nightly.YYYYMMDD.<sha>` (#590/#591 D5).
///
/// Mirrors the feed-signer's `parse_nightly_build` (SPEC §10.3) so the beacon ages an installed
/// nightly on the SAME scale the signed manifest's nightly `build`/floor use. `None` when the
/// `-nightly.` date segment is not exactly eight decimal digits — a malformed local nightly is
/// treated as un-ageable (fail-safe: a rollback refuses what it cannot prove is at/above the floor)
/// rather than mis-packed onto the stable scale.
#[must_use]
fn nightly_build_date(version: &str) -> Option<u64> {
    let after = version.split("-nightly.").nth(1)?;
    let date = after.split('.').next().unwrap_or_default();
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    date.parse::<u64>().ok()
}

/// How a tracked component's artifact is installed on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMethod {
    /// Replace a single executable in place with the staged bytes (digstore, dig-dns, and the
    /// beacon itself). The broker owns the swap + retry-on-lock (SPEC §9.5).
    RawBinary,
    /// A Windows MSI, installed silently: `msiexec /i <pkg> /qn /norestart`. A service-backed
    /// component (dig-node) does NOT self-manage its service stop/start across an update — the
    /// applier stops the service before this runs and restarts it after, so the `/norestart` MSI
    /// swaps an UNLOCKED file rather than deferring the swap over a running, locked binary (#666).
    WindowsMsi,
    /// A macOS flat package, installed silently: `installer -pkg <pkg> -target /`.
    MacosPkg,
    /// A Debian package, installed silently: `dpkg -i <pkg>`.
    LinuxDeb,
}

/// Whether the beacon may act on a component whose installed version it cannot READ.
///
/// Every tracked component is health-gated on the version it reports (SPEC §9.5/§9.6), so a probe
/// that comes back unreadable is the one answer the planner cannot reason from. What to DO about it
/// differs by component, and getting that wrong is expensive in opposite directions:
///
/// - For a CLI or a service executable, which certainly answers `--version`, an unreadable answer
///   means the installed bytes are corrupt or partial — and reinstalling from the verified artifact
///   is exactly the repair. That is [`Self::NotRequired`], the behaviour every such component keeps.
/// - For a component that may not answer at all — `dig-app` until dig_ecosystem#1749 lands — the
///   same reinstall would download it, install it, fail its health gate and roll it back on EVERY
///   pass, forever, burying the real cause under churn. That is [`Self::Required`]: the beacon acts
///   only on a build that has PROVEN which version it is, and reports the hold otherwise.
///
/// The distinction is deliberately keyed on the host's own probe answer rather than on a flag
/// someone must flip: the pass a held component gains `--version` is the pass it starts updating
/// normally, with its full health gate, and no change here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VersionEvidence {
    /// Act on the component regardless — an unreadable version is a corrupt install to be repaired
    /// by reinstalling. The default, and the behaviour of every component that answers `--version`.
    #[default]
    NotRequired,
    /// Act only on a component that has proven its version by answering the §9.6 probe; otherwise
    /// HOLD it ([`HeldComponent`]) and report why.
    Required,
}

/// Where + how one tracked component installs on THIS host.
///
/// A component is a *binary SET*, not a single file (#666 Bug A): its [`Self::dest`] primary PLUS
/// every byte-identical ALIAS it ships under ([`Self::aliases`] — `digs≡digstore`, `digd≡dig-dns`,
/// `dign≡dig-node`, canonical skill). Every binary in the set MUST be replaced + health-checked in
/// the same pass, or a beacon that advances the primary while leaving an alias frozen at its
/// install-time version silently reports the update as applied when it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentTarget {
    /// The manifest component name (e.g. `"digstore"`).
    pub name: String,
    /// How its artifact is applied on this platform.
    pub method: InstallMethod,
    /// The installed executable's path — probed for the installed version and, for a
    /// [`InstallMethod::RawBinary`], the file that is replaced.
    pub dest: PathBuf,
    /// The byte-identical alias binaries this component also owns on disk (siblings of `dest`,
    /// `.exe` on Windows). Empty for a component with no alias. Each is refreshed from the SAME
    /// verified bytes as the primary and version-checked alongside it (#666 Bug A).
    pub aliases: Vec<PathBuf>,
    /// The OS service this component's binary belongs to, as its reverse-DNS id (e.g.
    /// `net.dignetwork.dig-node`), when the component runs as a service whose executable is held
    /// open while it runs. `None` for a component that is not service-backed. A service-backed
    /// component's binary is file-locked while the service runs, so the applier MUST stop the
    /// service before replacing it and restart it after (#666 Bug B).
    pub service: Option<String>,
    /// Whether this component must PROVE its installed version before the beacon acts on it
    /// ([`VersionEvidence`]). Default ([`VersionEvidence::NotRequired`]) for everything that
    /// answers `--version`.
    pub evidence: VersionEvidence,
}

impl ComponentTarget {
    /// Every on-disk binary this component owns — the primary [`Self::dest`] FIRST, then each
    /// byte-identical alias. The applier replaces + health-checks the whole set (#666 Bug A).
    pub fn binaries(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.dest.as_path()).chain(self.aliases.iter().map(PathBuf::as_path))
    }

    /// The OS service id this component's binary belongs to, if it is service-backed (#666 Bug B).
    #[must_use]
    pub fn service_id(&self) -> Option<&str> {
        self.service.as_deref()
    }
}

/// The install catalog: the tracked components' targets on this host. Overridable so tests and the
/// installer can substitute their own destinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    targets: Vec<ComponentTarget>,
}

impl Catalog {
    /// Build a catalog from explicit targets.
    #[must_use]
    pub fn new(targets: Vec<ComponentTarget>) -> Self {
        Self { targets }
    }

    /// The default tracked-component catalog on `platform` (SPEC §10.3) — channel-agnostic, since
    /// both channels track the SAME component set, differing only in which release each resolves.
    /// dig-node installs as a native package (MSI/pkg/deb) and runs as an OS service the applier
    /// stops before + restarts after its replace (#666 Bug B); digstore, dig-dns and the beacon
    /// itself are raw-binary replaces. Each aliased component (digs/digd/dign) owns its alias too.
    ///
    /// Destinations are resolved from the RUNNING beacon's own location (#581): the universal
    /// installer places every DIG binary — including `dig-updater` — in one install bin dir, so the
    /// components install as SIBLINGS of the beacon. This auto-matches wherever the installer put
    /// things (e.g. `%LOCALAPPDATA%\Programs\DigStore\bin`) with no cross-repo path config, and — the
    /// bug this fixes — means the beacon installs to + health-probes the SAME binaries the user
    /// actually runs, instead of a decoupled hardcoded `C:\Program Files\DIG`. Overridable so the
    /// installer (#504-H) and tests can substitute their own destinations.
    #[must_use]
    pub fn alpha_defaults(platform: &Platform) -> Self {
        Self::alpha_defaults_in(
            &resolve_install_root(std::env::current_exe().ok(), platform),
            platform,
        )
    }

    /// [`Self::alpha_defaults`] with the install root supplied explicitly — the pure core, so the
    /// per-component destinations + methods are unit-testable without depending on where the test
    /// binary happens to live.
    #[must_use]
    fn alpha_defaults_in(bin_dir: &Path, platform: &Platform) -> Self {
        let windows = platform.os == "windows";
        let exe = |stem: &str| -> PathBuf {
            bin_dir.join(if windows {
                format!("{stem}.exe")
            } else {
                stem.to_string()
            })
        };
        let package_method = if windows {
            InstallMethod::WindowsMsi
        } else if platform.os == "macos" {
            InstallMethod::MacosPkg
        } else {
            InstallMethod::LinuxDeb
        };
        Self::new(vec![
            ComponentTarget {
                name: "dig-node".into(),
                method: package_method,
                dest: exe("dig-node"),
                // dig-node ships the byte-identical alias `dign` (v0.31.0, #548) and runs as the
                // OS service `net.dignetwork.dig-node`, whose executable is held open while it runs.
                aliases: vec![exe("dign")],
                service: Some("net.dignetwork.dig-node".into()),
                evidence: VersionEvidence::NotRequired,
            },
            ComponentTarget {
                name: "digstore".into(),
                method: InstallMethod::RawBinary,
                dest: exe("digstore"),
                // digstore ships the byte-identical alias `digs` (#434).
                aliases: vec![exe("digs")],
                service: None,
                evidence: VersionEvidence::NotRequired,
            },
            ComponentTarget {
                name: "dig-dns".into(),
                method: InstallMethod::RawBinary,
                dest: exe("dig-dns"),
                // dig-dns ships the byte-identical alias `digd` (v0.12.0, #548) — the #666 Bug A
                // binary a pre-fix beacon left frozen at its install-time version.
                aliases: vec![exe("digd")],
                service: None,
                evidence: VersionEvidence::NotRequired,
            },
            ComponentTarget {
                name: BEACON_COMPONENT_NAME.into(),
                method: InstallMethod::RawBinary,
                dest: exe(BEACON_COMPONENT_NAME),
                aliases: vec![],
                service: None,
                evidence: VersionEvidence::NotRequired,
            },
            ComponentTarget {
                name: DIG_APP_COMPONENT_NAME.into(),
                method: InstallMethod::RawBinary,
                dest: exe(DIG_APP_COMPONENT_NAME),
                // dig-app's release publishes a `dign` binary too, but that is its own separate user
                // CLI — NOT a byte-identical alias of dig-app — and the `dign` filename in this bin
                // dir is already dig-node's alias. Two components resolving one installed filename
                // would overwrite each other on every pass (SPEC §9.7(4)), so dig-app claims none.
                aliases: vec![],
                // A per-user tray agent, not a machine service (SPEC §9.7(1)): its autostart is a
                // per-user LaunchAgent / systemd USER unit / `HKCU\…\Run` value the elevated beacon
                // must not drive. So there is nothing for the applier to stop — the move-aside swap
                // replaces the binary under the running process, which keeps executing the old image
                // until the user's next login. Killing it to install an update would destroy an
                // unlocked identity session to deliver a background task.
                service: None,
                // Until dig-app can answer `--version` (dig_ecosystem#1749) the beacon HOLDS it
                // rather than reinstalling-and-rolling-back every pass.
                evidence: VersionEvidence::Required,
            },
        ])
    }

    /// The target for `name`, if this host tracks that component.
    #[must_use]
    pub fn target(&self, name: &str) -> Option<&ComponentTarget> {
        self.targets.iter().find(|t| t.name == name)
    }
}

/// One component's planned action for this pass: what to do, and everything needed to do it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedComponent {
    /// The component name.
    pub name: String,
    /// How to apply it.
    pub method: InstallMethod,
    /// The installed executable path (probe + raw-binary replace target).
    pub dest: PathBuf,
    /// The byte-identical alias binaries refreshed from the SAME verified bytes as `dest` and
    /// version-checked alongside it (#666 Bug A) — copied from the component's
    /// [`ComponentTarget::aliases`].
    pub aliases: Vec<PathBuf>,
    /// The manifest's human version for this build.
    pub version: String,
    /// The manifest's monotonic build number.
    pub build: u64,
    /// The digest from the RE-VERIFIED manifest — the authority the staged bytes are re-hashed
    /// against immediately before install (SPEC §8.3), NOT the digest the worker reported.
    pub expected_digest: String,
    /// The staged, worker-downloaded file to install from.
    pub staged_path: PathBuf,
    /// Install / Update / Skip, from the shared decision matrix.
    pub action: UpdateAction,
    /// The human-readable version transition (e.g. `"v0.14.0 → v0.15.0 (update)"`).
    pub summary: String,
    /// The installed version detected before this pass (`None` if absent), packed for the
    /// rollback-floor comparison — the build a rollback would reinstate.
    pub installed_build: Option<u64>,
}

/// A tracked component this pass will NOT act on, and why.
///
/// A hold is a first-class, REPORTED outcome, not a silent omission: the component is deliberately
/// absent from [`Plan::components`] — so no code path can install, health-gate or roll it back — and
/// the applier turns each hold into a [`ComponentResult::Held`](crate::ComponentResult::Held) line
/// in the pass report carrying [`Self::reason`]. Fail-closed and legible, rather than a pass that
/// quietly claims success while one component was never considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldComponent {
    /// The manifest component name.
    pub name: String,
    /// Why it was held, in terms an operator can act on.
    pub reason: String,
}

/// The full pass plan: one entry per tracked, platform-relevant component in the manifest — split
/// into what will be ACTED on and what is HELD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The planned components, manifest order.
    pub components: Vec<PlannedComponent>,
    /// The tracked components deliberately not acted on this pass ([`HeldComponent`]).
    pub held: Vec<HeldComponent>,
}

impl Plan {
    /// Enumerate + plan against the RE-VERIFIED `manifest`, the worker's `staged` artifacts, this
    /// host's `catalog`, and `platform`, using `detect` to read each component's installed version.
    ///
    /// Untracked components (not in the catalog) and components with no artifact for this platform
    /// are skipped entirely. A tracked, platform-relevant component whose artifact the worker did
    /// NOT stage is a [`BrokerError::StagedArtifactMissing`]: the plan is structurally incomplete
    /// and the pass must not proceed.
    ///
    /// # Errors
    ///
    /// [`BrokerError::StagedArtifactMissing`] if the manifest names a platform artifact absent from
    /// `staged`.
    pub fn build(
        manifest: &Manifest,
        staged: &[StagedArtifact],
        catalog: &Catalog,
        platform: &Platform,
        detect: &dyn Fn(&Path) -> DetectedVersion,
    ) -> Result<Self, BrokerError> {
        let mut components = Vec::new();
        let mut held = Vec::new();
        for component in &manifest.components {
            let Some(target) = catalog.target(&component.name) else {
                continue; // a component this host does not track
            };
            let Some(artifact) = component.artifact(&platform.os, &platform.arch) else {
                continue; // nothing for this OS/arch
            };

            let detected = detect(&target.dest);
            // Decide the HOLD before anything else: a component the beacon will not act on needs no
            // staged bytes, so requiring them here would let a missing download fault the whole pass
            // over a component nobody was going to touch.
            if let Some(reason) = hold_reason(target, &detected) {
                held.push(HeldComponent {
                    name: component.name.clone(),
                    reason,
                });
                continue;
            }

            // The worker-reported `staged_path` is carried verbatim here and is NOT trusted: it is
            // canonicalized + confined to the broker-owned staging dir by
            // [`crate::install::contained_staged_path`] at install time (SPEC §8.3), before any byte
            // is read. Keeping planning pure of filesystem I/O leaves that guard at the single
            // point where the bytes are actually hashed + installed.
            let staged_path = staged
                .iter()
                .find(|s| {
                    s.component == component.name && s.os == platform.os && s.arch == platform.arch
                })
                .map(|s| PathBuf::from(&s.staged_path))
                .ok_or_else(|| BrokerError::StagedArtifactMissing {
                    component: component.name.clone(),
                    os: platform.os.clone(),
                    arch: platform.arch.clone(),
                })?;

            let installed_build = installed_build(&detected);
            let decision = decide(&detected, &component.version);
            // #666 F3: the enumeration decision must key on the WHOLE binary set, not just the
            // primary `dest`. A prior pass may have advanced the primary but left an alias stale
            // (a transient alias lock → the component reported `Deferred` with primary-new/alias-old,
            // no rollback). If we keyed only on the primary here, we would see it current → `Skip` →
            // the stale alias would NEVER be re-refreshed and Bug A would recur. So: when the primary
            // says `Skip` but ANY alias is missing or reports a different version, re-drive the
            // component as an `Update` so the applier refreshes + health-checks the whole set.
            let (action, summary) = redrive_for_stale_alias(
                target,
                &component.version,
                decision.action,
                decision.summary,
                detect,
            );
            components.push(PlannedComponent {
                name: component.name.clone(),
                method: target.method,
                dest: target.dest.clone(),
                aliases: target.aliases.clone(),
                version: component.version.clone(),
                build: component.build,
                expected_digest: artifact.sha256.clone(),
                staged_path,
                action,
                summary,
                installed_build,
            });
        }
        Ok(Self { components, held })
    }

    /// The components this pass will actually act on (Install or Update) — Skip entries filtered
    /// out.
    pub fn actionable(&self) -> impl Iterator<Item = &PlannedComponent> {
        self.components
            .iter()
            .filter(|c| c.action != UpdateAction::Skip)
    }
}

/// The installed build a probe answer packs to, on the same monotonic scale the signed manifest uses
/// ([`pack_build`]) — the build a rollback would reinstate. `None` when nothing is installed, or when
/// what it printed carries no version this beacon can age.
///
/// The version is the LAST whitespace-separated token, because the conventional `--version` line is
/// `<program> <version>` (clap's default) and a bare `<version>` is the same token.
#[must_use]
fn installed_build(detected: &DetectedVersion) -> Option<u64> {
    match detected {
        DetectedVersion::Present(raw) => pack_build(raw.split_whitespace().last().unwrap_or("")),
        DetectedVersion::Absent => None,
    }
}

/// Why `target` is HELD this pass, or `None` to plan it normally ([`VersionEvidence`]).
///
/// A component that does not require version evidence is never held. One that does is held unless
/// its probe answer packs to a real build — i.e. unless the build on disk has PROVEN which version
/// it is. Both failing answers are held rather than acted on, for the same reason:
///
/// - *installed but mute* — the beacon cannot tell whether an update is needed, and cannot verify one
///   afterwards, so installing would fail the §9.5 health gate and roll back on every pass forever.
/// - *not installed* — a fresh install could not be health-gated either, and placing a per-user
///   agent nobody installed is the installer's job, not the beacon's (SPEC §9.7(2)).
///
/// The reason names the missing capability, so the pass report says what is wrong and what would fix
/// it rather than reporting a component-shaped silence.
#[must_use]
fn hold_reason(target: &ComponentTarget, detected: &DetectedVersion) -> Option<String> {
    if target.evidence == VersionEvidence::NotRequired || installed_build(detected).is_some() {
        return None;
    }
    let name = &target.name;
    let dest = target.dest.display();
    Some(match detected {
        DetectedVersion::Present(_) => format!(
            "held: {name} is installed at {dest} but did not report a readable version, so an \
             update could not be verified (it must answer `--version` and exit — \
             dig_ecosystem#1749); nothing was installed, changed or rolled back"
        ),
        DetectedVersion::Absent => format!(
            "held: {name} is not installed at {dest}; the beacon updates it but does not place it \
             (run the DIG installer), and an install it cannot version-check via `--version` could \
             not be health-gated"
        ),
    })
}

/// Re-drive an aliased component as an `Update` when the PRIMARY looks current (`Skip`) but ANY of
/// its byte-identical aliases is missing or on a different version (#666 F3).
///
/// Enumeration must treat a component as a binary SET: keying the Install/Skip decision on the
/// primary alone would let a stale alias — left behind by a prior pass whose alias replace deferred
/// — go unnoticed forever (primary current → `Skip` → the alias is never re-refreshed). When the
/// primary is already actionable (`Install`/`Update`), the applier refreshes the whole set anyway,
/// so the primary decision is returned unchanged; only a `Skip` primary is escalated.
fn redrive_for_stale_alias(
    target: &ComponentTarget,
    version: &str,
    primary_action: UpdateAction,
    primary_summary: String,
    detect: &dyn Fn(&Path) -> DetectedVersion,
) -> (UpdateAction, String) {
    if primary_action != UpdateAction::Skip {
        return (primary_action, primary_summary);
    }
    for alias in &target.aliases {
        if decide(&detect(alias), version).action != UpdateAction::Skip {
            return (
                UpdateAction::Update,
                format!(
                    "v{version} (primary current, but alias {} is out of date — refreshing the set)",
                    alias.display()
                ),
            );
        }
    }
    (primary_action, primary_summary)
}

/// Resolve the install root — the directory the beacon installs components INTO — from the running
/// beacon's own executable path (#581).
///
/// `current_exe` is the resolved path of the running beacon (`std::env::current_exe()` in
/// production; injected in tests). Its PARENT is the install bin dir, because the universal
/// installer drops `dig-updater(.exe)` there alongside every other DIG binary — so components
/// install as its siblings and the beacon probes exactly where the user's binaries live. A
/// `None` (unresolvable exe) or a parentless path falls back to [`default_install_root`], so a
/// pass never aborts on an exe-path lookup failure.
#[must_use]
fn resolve_install_root(current_exe: Option<PathBuf>, platform: &Platform) -> PathBuf {
    current_exe
        .as_deref()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_install_root(platform))
}

/// The conventional per-OS install root, used ONLY as the fallback when the beacon's own exe path
/// cannot be resolved ([`resolve_install_root`]). Not the primary source of truth — the running
/// beacon's location is (#581).
#[must_use]
fn default_install_root(platform: &Platform) -> PathBuf {
    if platform.os == "windows" {
        let program_files =
            std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
        PathBuf::from(program_files).join("DIG")
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_updater_trust::{Artifact, Component};

    fn platform() -> Platform {
        Platform {
            os: "linux".into(),
            arch: "x64".into(),
        }
    }

    fn manifest_one(name: &str, version: &str, build: u64, digest: &str) -> Manifest {
        Manifest {
            schema: 1,
            root_version: 1,
            sequence: 1,
            generated: 1,
            expires: u64::MAX,
            rollback_floor_build: 0,
            components: vec![Component {
                name: name.into(),
                version: version.into(),
                build,
                artifacts: vec![Artifact {
                    os: "linux".into(),
                    arch: "x64".into(),
                    url: "https://x/y".into(),
                    sha256: digest.into(),
                    size: 1,
                }],
            }],
        }
    }

    fn staged(name: &str, path: &str) -> StagedArtifact {
        StagedArtifact {
            component: name.into(),
            version: "0.15.0".into(),
            build: 15_000,
            os: "linux".into(),
            arch: "x64".into(),
            sha256: "deadbeef".into(),
            size: 1,
            staged_path: path.into(),
        }
    }

    fn catalog() -> Catalog {
        Catalog::new(vec![ComponentTarget {
            name: "digstore".into(),
            method: InstallMethod::RawBinary,
            dest: PathBuf::from("/opt/dig/digstore"),
            aliases: vec![PathBuf::from("/opt/dig/digs")],
            service: None,
            evidence: VersionEvidence::NotRequired,
        }])
    }

    /// A manifest naming SEVERAL components, so a test can vary ONE component's probe answer while
    /// keeping the others as truthful controls (a single-component fixture cannot distinguish
    /// "this component was held" from "the whole pass was abandoned").
    fn manifest_of(components: &[(&str, &str, u64)]) -> Manifest {
        Manifest {
            components: components
                .iter()
                .map(|(name, version, build)| Component {
                    name: (*name).into(),
                    version: (*version).into(),
                    build: *build,
                    artifacts: vec![Artifact {
                        os: "linux".into(),
                        arch: "x64".into(),
                        url: "https://x/y".into(),
                        sha256: "deadbeef".into(),
                        size: 1,
                    }],
                })
                .collect(),
            ..manifest_one("unused", "0.0.0", 0, "deadbeef")
        }
    }

    /// A catalog holding `digstore` (an ordinary component that answers `--version`) beside
    /// `dig-app` (which requires version evidence before the beacon will act on it).
    fn catalog_with_dig_app() -> Catalog {
        Catalog::new(vec![
            ComponentTarget {
                name: "digstore".into(),
                method: InstallMethod::RawBinary,
                dest: PathBuf::from("/opt/dig/digstore"),
                aliases: vec![],
                service: None,
                evidence: VersionEvidence::NotRequired,
            },
            ComponentTarget {
                name: DIG_APP_COMPONENT_NAME.into(),
                method: InstallMethod::RawBinary,
                dest: PathBuf::from("/opt/dig/dig-app"),
                aliases: vec![],
                service: None,
                evidence: VersionEvidence::Required,
            },
        ])
    }

    /// A probe that answers for `digstore` and stays MUTE for `dig-app` — the pre-#1749 reality on a
    /// host where both are installed. Only the dig-app answer varies; digstore is the control.
    fn digstore_answers_dig_app_is_mute(path: &Path) -> DetectedVersion {
        if path.ends_with("dig-app") {
            DetectedVersion::Present(String::new()) // installed, but reported no version
        } else {
            DetectedVersion::Present("digstore 0.14.0".into())
        }
    }

    #[test]
    fn dig_app_is_tracked_as_a_per_user_daemon_that_claims_no_alias() {
        // SPEC §9.7: dig-app publishes a raw per-platform binary, is replaced by the move-aside swap,
        // and runs as a per-USER autostart — so it declares NO machine service for the applier to
        // stop (stopping it would need the user's session and would destroy an unlocked agent), and
        // NO alias: its release also publishes `dign`, but that installed filename is already
        // dig-node's byte-identical alias, and one filename claimed by two components would have them
        // overwrite each other on every pass (SPEC §9.7(4)).
        // `join` keeps the expected paths on the host's separators, so the assertions hold on both
        // Windows and Linux (a literal `/opt/...` is one un-splittable component on Windows).
        let bin = PathBuf::from("opt").join("dig").join("bin");
        let cat = Catalog::alpha_defaults_in(&bin, &platform());
        let dig_app = cat
            .target(DIG_APP_COMPONENT_NAME)
            .expect("dig-app is a tracked component (dig_ecosystem#1746)");

        assert_eq!(dig_app.method, InstallMethod::RawBinary);
        assert_eq!(dig_app.dest, bin.join("dig-app"));
        assert_eq!(dig_app.service_id(), None);
        assert!(dig_app.aliases.is_empty());
        // The `dign` filename dig-app must NOT claim is claimed by dig-node — which is what makes
        // the empty `aliases` above load-bearing rather than incidental.
        assert!(cat
            .target("dig-node")
            .unwrap()
            .aliases
            .contains(&bin.join("dign")));
    }

    #[test]
    fn only_dig_app_requires_version_evidence() {
        // The policy is PER COMPONENT: every component that answers `--version` keeps the ordinary
        // reinstall-to-repair behaviour, so this is not a global weakening of the update path.
        let cat = Catalog::alpha_defaults_in(Path::new("/opt/dig/bin"), &platform());
        assert_eq!(
            cat.target(DIG_APP_COMPONENT_NAME).unwrap().evidence,
            VersionEvidence::Required
        );
        for component in ["dig-node", "digstore", "dig-dns", BEACON_COMPONENT_NAME] {
            assert_eq!(
                cat.target(component).unwrap().evidence,
                VersionEvidence::NotRequired,
                "{component} answers --version, so it is repaired by reinstalling"
            );
        }
    }

    #[test]
    fn a_component_that_cannot_report_its_version_is_held_while_its_siblings_still_update() {
        // The fail-closed core (dig_ecosystem#1746/#1749). dig-app is installed but mute, so it is
        // HELD: no plan entry at all, hence nothing the applier could install, health-gate or roll
        // back. digstore — the control — is on 0.14.0 against a 0.15.0 manifest and MUST still be
        // planned as an Update: holding one component must not abandon the pass.
        let m = manifest_of(&[
            ("digstore", "0.15.0", 15_000),
            ("dig-app", "3.4.0", 3_004_000),
        ]);
        let plan = Plan::build(
            &m,
            &[
                staged("digstore", "/staging/digstore"),
                staged("dig-app", "/staging/dig-app"),
            ],
            &catalog_with_dig_app(),
            &platform(),
            &digstore_answers_dig_app_is_mute,
        )
        .unwrap();

        let names: Vec<&str> = plan.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["digstore"],
            "a held component must never reach the plan the applier acts on"
        );
        assert_eq!(plan.components[0].action, UpdateAction::Update);

        let held = plan
            .held
            .iter()
            .find(|h| h.name == DIG_APP_COMPONENT_NAME)
            .expect("dig-app is reported as HELD, never silently omitted");
        assert!(
            held.reason.contains("--version"),
            "the hold must name its cause so a pass is never a vacuous success: {}",
            held.reason
        );
    }

    #[test]
    fn a_component_requiring_evidence_is_held_when_it_is_not_installed_at_all() {
        // Absent is held too, not Installed: the beacon UPDATES a per-user daemon it can verify, and
        // an install it could not health-gate would be attempt-fail-rollback churn on every pass.
        let m = manifest_of(&[("dig-app", "3.4.0", 3_004_000)]);
        let plan = Plan::build(
            &m,
            &[staged("dig-app", "/staging/dig-app")],
            &catalog_with_dig_app(),
            &platform(),
            &|_| DetectedVersion::Absent,
        )
        .unwrap();
        assert!(plan.components.is_empty());
        assert_eq!(plan.held.len(), 1);
        assert!(plan.held[0].reason.contains("not installed"));
    }

    #[test]
    fn a_component_requiring_evidence_updates_normally_once_it_answers_the_probe() {
        // THE GATE OPENS BY ITSELF. The hold is keyed on the host's own probe answer, not on a flag
        // someone must remember to flip, so the pass dig_ecosystem#1749 ships turns dig-app into an
        // ordinary health-gated component with NO further change here. An implementation that simply
        // never plans dig-app would pass every other test in this file and fail this one.
        let m = manifest_of(&[("dig-app", "3.4.0", 3_004_000)]);
        let plan = Plan::build(
            &m,
            &[staged("dig-app", "/staging/dig-app")],
            &catalog_with_dig_app(),
            &platform(),
            &|_| DetectedVersion::Present("dig-app 3.3.0".into()),
        )
        .unwrap();
        assert!(
            plan.held.is_empty(),
            "a component that proved its version is not held"
        );
        assert_eq!(plan.components[0].action, UpdateAction::Update);
        assert_eq!(
            plan.components[0].installed_build,
            Some(3_003_000),
            "and it is aged on the same packed scale as every other component"
        );
    }

    #[test]
    fn an_unreadable_version_still_reinstalls_a_component_that_does_not_require_evidence() {
        // The control for the policy: digstore answers `--version`, so an unreadable answer means a
        // corrupt or partial install and reinstalling from the verified artifact is the REPAIR. Held
        // must not leak into the components that rely on that behaviour.
        let m = manifest_of(&[("digstore", "0.15.0", 15_000)]);
        let plan = Plan::build(
            &m,
            &[staged("digstore", "/staging/digstore")],
            &catalog_with_dig_app(),
            &platform(),
            &|_| DetectedVersion::Present(String::new()),
        )
        .unwrap();
        assert!(plan.held.is_empty());
        assert_eq!(plan.components[0].action, UpdateAction::Update);
    }

    #[test]
    fn a_held_component_does_not_need_a_staged_artifact() {
        // The hold is decided BEFORE the staged-artifact lookup, because a component that will not be
        // installed needs no bytes. Deciding it after would make a missing dig-app download fault the
        // whole pass (`StagedArtifactMissing`) over a component nobody was going to touch.
        let m = manifest_of(&[("dig-app", "3.4.0", 3_004_000)]);
        let plan = Plan::build(&m, &[], &catalog_with_dig_app(), &platform(), &|_| {
            DetectedVersion::Present(String::new())
        })
        .expect("a held component with no staged bytes is not a structurally incomplete plan");
        assert_eq!(plan.held.len(), 1);
    }

    #[test]
    fn pack_build_matches_the_feed_signer_encoding() {
        // These MUST equal the feed-signer's `Version::build_number` (SPEC §10.3).
        assert_eq!(pack_build("0.29.0"), Some(29_000));
        assert_eq!(pack_build("0.13.1"), Some(13_001));
        assert_eq!(pack_build("1.0.0"), Some(1_000_000));
        assert_eq!(pack_build("v0.15.0"), Some(15_000));
        assert_eq!(pack_build("garbage"), None);
        assert_eq!(pack_build("1.2"), None);
        assert_eq!(pack_build("1.1000.0"), None);
    }

    #[test]
    fn pack_build_of_a_nightly_version_is_its_utc_date_not_the_semver_core() {
        // A nightly `--version` is aged by its YYYYMMDD build DATE — the same scale the feed-signer
        // stamps on the nightly manifest `build`/floor (SPEC §10.3, #591 D5) — NOT by semver-packing
        // its `X.Y.Z` core (which would land on the stable thousands-scale and mis-compare against a
        // date-scale floor). Here 0.9.0 would semver-pack to 9_000, but the nightly build is the date.
        assert_eq!(
            pack_build("0.9.0-nightly.20260714.abc1234"),
            Some(20_260_714)
        );
        assert_eq!(
            pack_build("0.31.1-nightly.20251231.deadbeef"),
            Some(20_251_231)
        );
        assert_eq!(pack_build("1.2.3-nightly.20260101.f00"), Some(20_260_101));
    }

    #[test]
    fn pack_build_of_a_nightly_version_with_a_bad_date_is_unageable() {
        // A nightly-SHAPED string with a malformed date is un-ageable (None) — it must NOT silently
        // fall through to semver-packing its `X.Y.Z` core onto the wrong scale. A rollback then
        // refuses what it cannot prove is at/above the floor (fail-safe), rather than mis-comparing.
        assert_eq!(pack_build("0.9.0-nightly.2026071.abc"), None); // 7-digit date
        assert_eq!(pack_build("0.9.0-nightly.notadate.abc"), None);
        assert_eq!(pack_build("0.9.0-nightly."), None); // empty date
    }

    #[test]
    fn pack_build_still_ignores_ordinary_non_nightly_prerelease_metadata() {
        // A plain `-rc`/`+build` suffix on a STABLE version is dropped and the semver core is packed
        // (unchanged behaviour) — only the `-nightly.` shape switches to the date scale.
        assert_eq!(pack_build("0.15.0-rc.1"), Some(15_000));
        assert_eq!(pack_build("0.15.0+build.7"), Some(15_000));
    }

    #[test]
    fn absent_component_is_planned_install() {
        let m = manifest_one("digstore", "0.15.0", 15_000, "deadbeef");
        let plan = Plan::build(
            &m,
            &[staged("digstore", "/staging/digstore")],
            &catalog(),
            &platform(),
            &|_| DetectedVersion::Absent,
        )
        .unwrap();
        assert_eq!(plan.components.len(), 1);
        assert_eq!(plan.components[0].action, UpdateAction::Install);
        assert_eq!(plan.components[0].expected_digest, "deadbeef");
        assert_eq!(plan.components[0].installed_build, None);
        assert_eq!(plan.actionable().count(), 1);
    }

    #[test]
    fn current_component_is_planned_skip() {
        let m = manifest_one("digstore", "0.15.0", 15_000, "deadbeef");
        let plan = Plan::build(
            &m,
            &[staged("digstore", "/staging/digstore")],
            &catalog(),
            &platform(),
            &|_| DetectedVersion::Present("digstore 0.15.0".into()),
        )
        .unwrap();
        assert_eq!(plan.components[0].action, UpdateAction::Skip);
        assert_eq!(plan.components[0].installed_build, Some(15_000));
        assert_eq!(plan.actionable().count(), 0);
    }

    #[test]
    fn older_component_is_planned_update() {
        let m = manifest_one("digstore", "0.15.0", 15_000, "deadbeef");
        let plan = Plan::build(
            &m,
            &[staged("digstore", "/staging/digstore")],
            &catalog(),
            &platform(),
            &|_| DetectedVersion::Present("digstore 0.14.0".into()),
        )
        .unwrap();
        assert_eq!(plan.components[0].action, UpdateAction::Update);
        assert_eq!(plan.components[0].installed_build, Some(14_000));
    }

    #[test]
    fn a_stale_alias_redrives_a_current_primary_as_an_update_666f3() {
        // #666 F3: the primary `digstore` is already at 0.15.0 (Skip on its own), but its alias
        // `digs` still reports 0.14.0. Keying only on the primary would Skip and leave the alias
        // stale forever; enumeration must re-drive the whole set as an Update.
        let m = manifest_one("digstore", "0.15.0", 15_000, "deadbeef");
        let plan = Plan::build(
            &m,
            &[staged("digstore", "/staging/digstore")],
            &catalog(),
            &platform(),
            &|p: &Path| {
                if p.ends_with("digs") {
                    DetectedVersion::Present("digstore 0.14.0".into()) // stale alias
                } else {
                    DetectedVersion::Present("digstore 0.15.0".into()) // current primary
                }
            },
        )
        .unwrap();
        assert_eq!(plan.components[0].action, UpdateAction::Update);
        assert_eq!(plan.actionable().count(), 1);
    }

    #[test]
    fn a_current_primary_and_current_alias_still_skips() {
        // The whole set is current → genuinely Skip (no spurious re-drive).
        let m = manifest_one("digstore", "0.15.0", 15_000, "deadbeef");
        let plan = Plan::build(
            &m,
            &[staged("digstore", "/staging/digstore")],
            &catalog(),
            &platform(),
            &|_| DetectedVersion::Present("digstore 0.15.0".into()),
        )
        .unwrap();
        assert_eq!(plan.components[0].action, UpdateAction::Skip);
    }

    #[test]
    fn untracked_component_is_skipped_entirely() {
        let m = manifest_one("some-future-tool", "1.0.0", 1_000_000, "deadbeef");
        let plan = Plan::build(&m, &[], &catalog(), &platform(), &|_| {
            DetectedVersion::Absent
        })
        .unwrap();
        assert!(
            plan.components.is_empty(),
            "untracked components are not planned"
        );
    }

    #[test]
    fn missing_staged_artifact_is_an_error() {
        let m = manifest_one("digstore", "0.15.0", 15_000, "deadbeef");
        // The manifest names a linux-x64 digstore artifact, but nothing was staged for it.
        let err = Plan::build(&m, &[], &catalog(), &platform(), &|_| {
            DetectedVersion::Absent
        })
        .expect_err("a manifest artifact with no staged file is incomplete");
        assert!(matches!(err, BrokerError::StagedArtifactMissing { .. }));
    }

    #[test]
    fn resolve_install_root_uses_the_exe_parent() {
        // The install root is the directory the beacon binary sits in. Built with `join` so the
        // separators are the host's — a literal `C:\...` string is a single un-splittable component
        // on Unix, which would make this pass on Windows yet fail on Linux.
        let bin = PathBuf::from("Programs").join("DigStore").join("bin");
        let exe = bin.join("dig-updater.exe");
        assert_eq!(resolve_install_root(Some(exe), &Platform::current()), bin);
    }

    #[test]
    fn resolve_install_root_falls_back_to_the_per_os_default_when_exe_is_unresolvable() {
        // A `None` exe path (current_exe() failed) must not abort a pass — it falls back to the
        // conventional per-OS root.
        let windows = Platform {
            os: "windows".into(),
            arch: "x64".into(),
        };
        assert!(resolve_install_root(None, &windows).ends_with("DIG"));

        let linux = Platform {
            os: "linux".into(),
            arch: "x64".into(),
        };
        assert_eq!(
            resolve_install_root(None, &linux),
            PathBuf::from("/usr/local/bin")
        );
    }

    #[test]
    fn alpha_defaults_in_installs_every_component_as_a_sibling_of_the_bin_dir() {
        let bin = Path::new("/opt/digstore/bin");
        let cat = Catalog::alpha_defaults_in(bin, &platform()); // linux platform
        assert_eq!(
            cat.target("dig-node").unwrap().dest,
            PathBuf::from("/opt/digstore/bin/dig-node")
        );
        assert_eq!(
            cat.target("digstore").unwrap().dest,
            PathBuf::from("/opt/digstore/bin/digstore")
        );
        assert_eq!(
            cat.target("dig-updater").unwrap().dest,
            PathBuf::from("/opt/digstore/bin/dig-updater")
        );
    }

    #[test]
    fn alpha_defaults_in_adds_the_exe_suffix_on_windows() {
        // The `windows` PLATFORM (not the host) drives the `.exe` suffix; `join` keeps the expected
        // paths on the host's separators so the assertion holds on both Windows and Linux.
        let bin = PathBuf::from("apps").join("DigStore").join("bin");
        let windows = Platform {
            os: "windows".into(),
            arch: "x64".into(),
        };
        let cat = Catalog::alpha_defaults_in(&bin, &windows);
        assert_eq!(
            cat.target("digstore").unwrap().dest,
            bin.join("digstore.exe")
        );
        // dig-node is a native package on Windows (MSI), but its PROBE dest still points at the
        // sibling exe the installer/MSI places in the bin dir.
        assert_eq!(
            cat.target("dig-node").unwrap().method,
            InstallMethod::WindowsMsi
        );
        assert_eq!(
            cat.target("dig-node").unwrap().dest,
            bin.join("dig-node.exe")
        );
    }

    #[test]
    fn alpha_defaults_installs_beside_the_running_beacon_not_a_hardcoded_dir() {
        // #581: the catalog must install to + probe the SAME directory the universal installer
        // placed the beacon in — derived from the beacon's OWN location — NOT a hardcoded
        // `C:\Program Files\DIG` / `/usr/local/bin`. `current_exe().parent()` is that install dir.
        let exe_dir = std::env::current_exe()
            .expect("current exe")
            .parent()
            .expect("exe has a parent")
            .to_path_buf();
        let cat = Catalog::alpha_defaults(&Platform::current());
        for name in ["dig-node", "digstore", "dig-dns", "dig-updater"] {
            let dest = &cat.target(name).unwrap().dest;
            assert!(
                dest.starts_with(&exe_dir),
                "{name} must install beside the beacon at {}, got {}",
                exe_dir.display(),
                dest.display()
            );
        }
    }

    #[test]
    fn each_aliased_component_enumerates_its_alias_as_a_dest_sibling() {
        // #666 Bug A: the applier replaces + health-checks the whole binary SET. The canonical
        // aliases (digs≡digstore, digd≡dig-dns, dign≡dig-node) are siblings of each primary.
        let bin = Path::new("/opt/dig/bin");
        let cat = Catalog::alpha_defaults_in(bin, &platform());
        for (component, alias) in [
            ("digstore", "digs"),
            ("dig-dns", "digd"),
            ("dig-node", "dign"),
        ] {
            let target = cat.target(component).unwrap();
            let binaries: Vec<PathBuf> = target.binaries().map(Path::to_path_buf).collect();
            assert!(
                binaries.contains(&bin.join(alias)),
                "{component} must enumerate its `{alias}` alias in its binary set"
            );
            assert_eq!(binaries[0], target.dest, "the primary binary comes first");
        }
        // The beacon itself ships no alias.
        assert!(cat
            .target(BEACON_COMPONENT_NAME)
            .unwrap()
            .aliases
            .is_empty());
    }

    #[test]
    fn only_dig_node_declares_a_managed_service() {
        // #666 Bug B: dig-node runs as the OS service `net.dignetwork.dig-node`; no other tracked
        // component is service-backed, so only it triggers the stop→replace→restart path.
        let cat = Catalog::alpha_defaults(&platform());
        assert_eq!(
            cat.target("dig-node").unwrap().service_id(),
            Some("net.dignetwork.dig-node")
        );
        for component in ["digstore", "dig-dns", BEACON_COMPONENT_NAME] {
            assert_eq!(cat.target(component).unwrap().service_id(), None);
        }
    }

    #[test]
    fn alpha_defaults_cover_the_tracked_set() {
        let cat = Catalog::alpha_defaults(&platform());
        assert!(cat.target("dig-node").is_some());
        assert!(cat.target("digstore").is_some());
        assert!(cat.target("dig-dns").is_some());
        assert!(cat.target("dig-updater").is_some());
        // dig-node is a native package on every OS; the raw binaries are raw.
        assert_eq!(
            cat.target("dig-node").unwrap().method,
            InstallMethod::LinuxDeb
        );
        assert_eq!(
            cat.target("digstore").unwrap().method,
            InstallMethod::RawBinary
        );
    }
}
