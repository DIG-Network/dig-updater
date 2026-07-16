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
            },
            ComponentTarget {
                name: "digstore".into(),
                method: InstallMethod::RawBinary,
                dest: exe("digstore"),
                // digstore ships the byte-identical alias `digs` (#434).
                aliases: vec![exe("digs")],
                service: None,
            },
            ComponentTarget {
                name: "dig-dns".into(),
                method: InstallMethod::RawBinary,
                dest: exe("dig-dns"),
                // dig-dns ships the byte-identical alias `digd` (v0.12.0, #548) — the #666 Bug A
                // binary a pre-fix beacon left frozen at its install-time version.
                aliases: vec![exe("digd")],
                service: None,
            },
            ComponentTarget {
                name: BEACON_COMPONENT_NAME.into(),
                method: InstallMethod::RawBinary,
                dest: exe(BEACON_COMPONENT_NAME),
                aliases: vec![],
                service: None,
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

/// The full pass plan: one entry per tracked, platform-relevant component in the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The planned components, manifest order.
    pub components: Vec<PlannedComponent>,
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
        for component in &manifest.components {
            let Some(target) = catalog.target(&component.name) else {
                continue; // a component this host does not track
            };
            let Some(artifact) = component.artifact(&platform.os, &platform.arch) else {
                continue; // nothing for this OS/arch
            };
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

            let detected = detect(&target.dest);
            let installed_build = match &detected {
                DetectedVersion::Present(raw) => {
                    pack_build(raw.split_whitespace().last().unwrap_or(""))
                }
                DetectedVersion::Absent => None,
            };
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
        Ok(Self { components })
    }

    /// The components this pass will actually act on (Install or Update) — Skip entries filtered
    /// out.
    pub fn actionable(&self) -> impl Iterator<Item = &PlannedComponent> {
        self.components
            .iter()
            .filter(|c| c.action != UpdateAction::Skip)
    }
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
        }])
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
