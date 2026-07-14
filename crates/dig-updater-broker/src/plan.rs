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

/// Pack a `major.minor.patch` version string into the manifest's monotonic `build` number.
///
/// Mirrors the feed-signer's `Version::build_number` (SPEC §10.3). Returns `None` for anything not
/// parseable as three decimal fields with `minor`/`patch` below the radix — the caller treats an
/// unparseable installed version as "cannot prove its age", which is the conservative default on
/// the rollback-floor check.
#[must_use]
pub fn pack_build(version: &str) -> Option<u64> {
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

/// How a tracked component's artifact is installed on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMethod {
    /// Replace a single executable in place with the staged bytes (digstore, dig-dns, and the
    /// beacon itself). The broker owns the swap + retry-on-lock (SPEC §9.5).
    RawBinary,
    /// A Windows MSI, installed silently: `msiexec /i <pkg> /qn /norestart`. The package
    /// self-manages the service stop/start.
    WindowsMsi,
    /// A macOS flat package, installed silently: `installer -pkg <pkg> -target /`.
    MacosPkg,
    /// A Debian package, installed silently: `dpkg -i <pkg>`.
    LinuxDeb,
}

/// Where + how one tracked component installs on THIS host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentTarget {
    /// The manifest component name (e.g. `"digstore"`).
    pub name: String,
    /// How its artifact is applied on this platform.
    pub method: InstallMethod,
    /// The installed executable's path — probed for the installed version and, for a
    /// [`InstallMethod::RawBinary`], the file that is replaced.
    pub dest: PathBuf,
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

    /// The alpha-channel defaults for the tracked component set on `platform` (SPEC §10.3). dig-node
    /// installs as a native package (MSI/pkg/deb) that self-manages its service; digstore, dig-dns
    /// and the beacon itself are raw-binary replaces.
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
            },
            ComponentTarget {
                name: "digstore".into(),
                method: InstallMethod::RawBinary,
                dest: exe("digstore"),
            },
            ComponentTarget {
                name: "dig-dns".into(),
                method: InstallMethod::RawBinary,
                dest: exe("dig-dns"),
            },
            ComponentTarget {
                name: BEACON_COMPONENT_NAME.into(),
                method: InstallMethod::RawBinary,
                dest: exe(BEACON_COMPONENT_NAME),
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
            components.push(PlannedComponent {
                name: component.name.clone(),
                method: target.method,
                dest: target.dest.clone(),
                version: component.version.clone(),
                build: component.build,
                expected_digest: artifact.sha256.clone(),
                staged_path,
                action: decision.action,
                summary: decision.summary,
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
        // The install root is the directory the beacon binary sits in.
        let exe = PathBuf::from(r"C:\Users\me\AppData\Local\Programs\DigStore\bin\dig-updater.exe");
        assert_eq!(
            resolve_install_root(Some(exe), &Platform::current()),
            PathBuf::from(r"C:\Users\me\AppData\Local\Programs\DigStore\bin")
        );
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
        let bin = Path::new(r"C:\apps\DigStore\bin");
        let windows = Platform {
            os: "windows".into(),
            arch: "x64".into(),
        };
        let cat = Catalog::alpha_defaults_in(bin, &windows);
        assert_eq!(
            cat.target("digstore").unwrap().dest,
            PathBuf::from(r"C:\apps\DigStore\bin\digstore.exe")
        );
        // dig-node is a native package on Windows (MSI), but its PROBE dest still points at the
        // sibling exe the installer/MSI places in the bin dir.
        assert_eq!(
            cat.target("dig-node").unwrap().method,
            InstallMethod::WindowsMsi
        );
        assert_eq!(
            cat.target("dig-node").unwrap().dest,
            PathBuf::from(r"C:\apps\DigStore\bin\dig-node.exe")
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
