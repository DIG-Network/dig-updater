//! Enumerating what is installed and PLANNING what to do about it.
//!
//! Given the RE-VERIFIED manifest (the authority — SPEC §9) and the artifacts the worker staged,
//! the broker decides, per tracked component, whether this pass should **Install** (nothing there
//! yet), **Update** (an older or unreadable build is present), or **Skip** (already current). It
//! does NOT re-implement that matrix: it detects the installed version and calls
//! [`dig_release_resolver`]'s shared [`decide`], the exact same logic `dig-installer` ships, so a
//! DIG box makes one consistent decision no matter which tool asks (SPEC §12, CLAUDE.md §4.1).
//!
//! A [`Catalog`] maps each tracked component to WHERE it installs, HOW ([`InstallMethod`]), and
//! WHAT ESTABLISHES which build is there ([`VersionEvidence`]) on this host. The alpha defaults
//! ([`Catalog::alpha_defaults`]) cover dig-node (native package), digstore / dig-updater / dig-dns
//! (raw binary, self-reported version) and dig-app (raw binary, content-digest evidence); they are
//! fully overridable so tests and the installer (#504-H) can point at their own destinations.
//!
//! Planning therefore has one step before the Install/Update/Skip matrix: WHICH evidence establishes
//! the installed version, chosen from the DECLARATION alone. A component whose version can only be
//! learned by running it, and which is not safe to run, is HELD ([`HeldComponent`]) **without being
//! executed** — because this process is SYSTEM/root. A component with content-digest evidence needs
//! no execution at all and is planned normally.

use std::path::{Path, PathBuf};

use dig_release_resolver::{decide, DetectedVersion, UpdateAction};

use dig_updater_trust::Manifest;
use dig_updater_worker::{Platform, StagedArtifact};

use crate::error::BrokerError;
use crate::hashing::DigestReader;
use crate::installed::InstalledBuilds;

/// The manifest component name the beacon tracks for ITSELF. The applier uses this to carve its
/// own component out of the ordinary per-component loop and apply it LAST, via a platform-specific
/// self-swap instead of the generic per-OS installer (SPEC §8.1, #504-F).
pub const BEACON_COMPONENT_NAME: &str = "dig-updater";

/// The manifest component name of the per-user identity agent (SPEC §9.7) — the one tracked
/// component that is a desktop tray daemon rather than a CLI or an OS service, and so the one that
/// requires [`VersionEvidence::UnsafeToProbe`].
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

/// WHAT establishes which build of a component is installed — and, for the two classes that would
/// have to ASK the binary, whether asking it `--version` is a question or an action (SPEC §9.7(5)).
///
/// The version probe is not a read. It is `Command::new(dest).arg("--version")`, executed by a
/// beacon running as SYSTEM / root, and its behaviour is decided entirely by the binary on disk. A
/// program that parses its arguments answers and exits; a program that ignores them does whatever it
/// does on startup — and `dig-app` ≤ 3.3.0 ignores them completely: `--version` boots its identity
/// agent, seals a fresh master seed on first run, and binds a browser-reachable signing WebSocket,
/// all under the machine account. Bounding that wait (see [`crate::probe`]) stops the pass hanging;
/// it does NOT un-run the side effects.
///
/// So this is a SAFETY declaration, not a preference. Three classes:
///
/// - [`Self::SafeToProbe`] — the binary is known to answer `--version` and exit. The beacon probes
///   it, and an unreadable answer means corrupt or partial bytes, repaired by reinstalling. Every
///   CLI and service component.
/// - [`Self::ArtifactDigest`] — the installed version is established by HASHING the file on disk
///   against the signed manifest artifact's `sha256`, so the binary is never executed at all, at any
///   version, on any path. The component is otherwise ordinary: planned, installed, health-gated
///   (by a re-hash) and rolled back like every other.
/// - [`Self::UnsafeToProbe`] — the version could only be learned by running the binary, and running
///   it may have side effects, so the beacon MUST NOT execute it. The component is [`HeldComponent`]:
///   not probed, not installed, not moved aside, not health-gated, not rolled back, and reported with
///   its reason every pass. (Its artifact IS still downloaded — the unprivileged worker stages every
///   manifest artifact and knows nothing of the catalog — but those bytes are digest-verified, land
///   in an Admin/SYSTEM-only directory, are never marked executable and are never read again: the
///   cost is bandwidth, not exposure.) This is the FAIL-CLOSED default for a component nobody has
///   established evidence for yet.
///
/// **The gate is declaration-driven, deliberately.** An earlier revision of this design decided the
/// hold from the probe's own answer, so that a component gaining `--version` would start updating
/// with no code change. That is elegant and wrong: learning the answer REQUIRES the exec this exists
/// to prevent, so the beacon would have booted a custody agent at machine privilege on every pass in
/// order to conclude that it should leave it alone. There is no version evidence obtainable by
/// executing a binary you have not established is safe to execute. Flipping a component to
/// [`Self::SafeToProbe`] is therefore a reviewed change, made once its released binary is known to
/// answer without booting — the cost of that review is the whole point.
///
/// **[`Self::ArtifactDigest`] exists so that review is not the only way out.** It is strictly
/// STRONGER than a probe rather than a convenient weakening: the evidence originates in the
/// root-signed manifest instead of in the binary's own claim, so a component cannot lie about its
/// version, and no `--version` behaviour has to be trusted at all. Prefer it over
/// [`Self::SafeToProbe`] for any component whose startup behaviour the beacon should not have to
/// vouch for. Deliberately NOT `Default`. A default would have to be one or the other, and the only one safe to
/// pick silently is the restrictive one — while the useful one, `SafeToProbe`, is a claim about a
/// specific binary that nobody should make by omission. Requiring every [`ComponentTarget`] to state
/// it means a component added later cannot inherit permission to be executed at machine privilege
/// from a `..Default::default()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionEvidence {
    /// The binary answers `--version` and exits: probe it, and reinstall it if the answer is
    /// unreadable. The behaviour of every component that ships a CLI entrypoint.
    SafeToProbe,
    /// The installed version is established by hashing the file at the destination against the signed
    /// manifest artifact's `sha256` — the binary is NEVER executed. Requires the component to declare
    /// no aliases (an alias would have to be compared some other way; see [`hold_reason`]).
    ArtifactDigest,
    /// The version could only be learned by executing the binary, and executing it may have side
    /// effects — so it is never executed and the component is always HELD ([`HeldComponent`]).
    UnsafeToProbe,
}

impl VersionEvidence {
    /// Whether establishing this component's installed version means EXECUTING it — the single
    /// question every exec site in the crate must be able to ask of a declaration alone.
    ///
    /// Exists so "may the beacon run this?" is answered in ONE place rather than re-derived at each
    /// call site as a pattern match that a fourth variant could silently fall through.
    #[must_use]
    pub fn requires_execution(self) -> bool {
        self == Self::SafeToProbe
    }
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
    /// Whether running this component's binary to ask its version is safe ([`VersionEvidence`]).
    /// Default ([`VersionEvidence::SafeToProbe`]) for everything known to answer `--version` and exit.
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
                evidence: VersionEvidence::SafeToProbe,
            },
            ComponentTarget {
                name: "digstore".into(),
                method: InstallMethod::RawBinary,
                dest: exe("digstore"),
                // digstore ships the byte-identical alias `digs` (#434).
                aliases: vec![exe("digs")],
                service: None,
                evidence: VersionEvidence::SafeToProbe,
            },
            ComponentTarget {
                name: "dig-dns".into(),
                method: InstallMethod::RawBinary,
                dest: exe("dig-dns"),
                // dig-dns ships the byte-identical alias `digd` (v0.12.0, #548) — the #666 Bug A
                // binary a pre-fix beacon left frozen at its install-time version.
                aliases: vec![exe("digd")],
                service: None,
                evidence: VersionEvidence::SafeToProbe,
            },
            ComponentTarget {
                name: BEACON_COMPONENT_NAME.into(),
                method: InstallMethod::RawBinary,
                dest: exe(BEACON_COMPONENT_NAME),
                aliases: vec![],
                service: None,
                evidence: VersionEvidence::SafeToProbe,
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
                // dig-app is kept current WITHOUT EVER BEING EXECUTED (dig_ecosystem#1803). Its
                // `--version` behaviour is irrelevant here by design: the installed build is
                // established by hashing this destination against the signed manifest artifact's
                // `sha256`, which works because the raw-binary install renames the verified,
                // digest-checked copy into `dest` — so a digest match IS "the current build is
                // installed", evidenced by the root-signed manifest rather than by the binary.
                //
                // NEVER flip this to `SafeToProbe`, and never add a version sidecar beside the
                // binary. dig-app <= 3.3.0 parses NO arguments — `--version` boots the identity
                // agent, seals a master seed on a first run and binds a loopback signing socket — and
                // that population is real and unobservable: v3.0.0/3.2.0/3.3.0 all shipped, and
                // dig-installer 0.30.0 (the first release to carry dig-app) predates dig-app 3.4.0 by
                // ~16 hours. The install root is per-user and user-writable (SPEC §9.7(2)), so any
                // file-based self-report there is FORGEABLE: an unprivileged user could claim "3.4.0"
                // beside a 3.0.0 binary and induce this SYSTEM/root beacon to boot it. A digest read
                // cannot be steered that way, because the expected value comes from the manifest.
                evidence: VersionEvidence::ArtifactDigest,
            },
        ])
    }

    /// The target for `name`, if this host tracks that component.
    #[must_use]
    pub fn target(&self, name: &str) -> Option<&ComponentTarget> {
        self.targets.iter().find(|t| t.name == name)
    }

    /// Every tracked target, in catalog order.
    ///
    /// Exists so the catalog can be audited as a WHOLE rather than component by name — the property
    /// that matters about [`VersionEvidence`] is "which components may the beacon execute?", and a
    /// by-name check cannot see a component added later.
    pub fn targets(&self) -> impl Iterator<Item = &ComponentTarget> {
        self.targets.iter()
    }
}

/// One build VARIANT of a component staged for this platform (dig_ecosystem#1912): the token that
/// names it, the manifest digest that authenticates it, and the staged file to install from.
///
/// A component with a single build has exactly one of these (the default, `variant == None`); a
/// component such as dig-app that ships a headless Linux build alongside the default has two, and the
/// applier picks the one this host can LOAD ([`crate::pass`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedVariant {
    /// The build variant token, or `None` for the default build.
    pub variant: Option<String>,
    /// The digest from the RE-VERIFIED manifest — the authority the staged bytes are re-hashed
    /// against immediately before install (SPEC §8.3), NOT the digest the worker reported.
    pub expected_digest: String,
    /// The staged, worker-downloaded file to install from.
    pub staged_path: PathBuf,
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
    /// The staged build variants for this platform, in SELECTION PREFERENCE order — the default
    /// (`variant == None`) FIRST (dig_ecosystem#1912). Always non-empty: `Plan::build` skips a
    /// component with no artifact for this platform. A single-build component has exactly one entry,
    /// so the applier's selection loop reduces to installing it, unchanged.
    pub variants: Vec<PlannedVariant>,
    /// Install / Update / Skip, from the shared decision matrix.
    pub action: UpdateAction,
    /// The human-readable version transition (e.g. `"v0.14.0 → v0.15.0 (update)"`).
    pub summary: String,
    /// The installed version detected before this pass (`None` if absent), packed for the
    /// rollback-floor comparison — the build a rollback would reinstate.
    pub installed_build: Option<u64>,
    /// What establishes this component's installed version, carried from its
    /// [`ComponentTarget::evidence`] so the applier's health gate uses the SAME evidence class the
    /// planner did. Without it the gate would fall back to a version PROBE — re-introducing, after
    /// the install, exactly the privileged exec the planner avoided before it.
    pub evidence: VersionEvidence,
}

impl PlannedComponent {
    /// The DEFAULT (preferred) staged variant — the first in [`Self::variants`], guaranteed to
    /// exist because a component with no artifact for this platform is never planned.
    #[must_use]
    pub fn primary(&self) -> &PlannedVariant {
        self.variants
            .first()
            .expect("a planned component always has at least its default variant")
    }
}

/// A tracked component this pass will NOT act on, and why.
///
/// A hold is a first-class, REPORTED outcome, not a silent omission: the component is deliberately
/// absent from [`Plan::components`] — so no code path can probe, install, health-gate or roll it
/// back — and the applier turns each hold into a
/// [`ComponentResult::Held`](crate::ComponentResult::Held) line in the pass report carrying
/// [`Self::reason`]. Fail-closed and legible, rather than a pass that quietly claims success while one
/// component was never considered.
///
/// "Not probed" is part of the guarantee, not a detail: the probe EXECUTES the binary from a
/// privileged parent ([`VersionEvidence`]), so a hold that had to look before it declined would be
/// no protection at all.
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
    /// host's `catalog`, and `platform`, establishing each component's installed version from the
    /// evidence class it declares: `detect` (which EXECUTES the binary) for
    /// [`VersionEvidence::SafeToProbe`], and `digest` (which only hashes it) for
    /// [`VersionEvidence::ArtifactDigest`].
    ///
    /// `recorded` is what this beacon last INSTALLED per component ([`InstalledBuilds`]), consulted
    /// ONLY to hold back an update that would move a digest-evidenced component BACKWARDS
    /// ([`guard_newer_installed`]) — never to permit one.
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
        digest: &DigestReader,
        recorded: &InstalledBuilds,
    ) -> Result<Self, BrokerError> {
        let mut components = Vec::new();
        let mut held = Vec::new();
        for component in &manifest.components {
            let Some(target) = catalog.target(&component.name) else {
                continue; // a component this host does not track
            };
            // Every build variant for this platform, default first (dig_ecosystem#1912). Empty →
            // nothing for this OS/arch, so the component is skipped exactly as before.
            let artifacts: Vec<&_> = component
                .artifacts_for(&platform.os, &platform.arch)
                .collect();
            if artifacts.is_empty() {
                continue; // nothing for this OS/arch
            }

            // Decide the HOLD FIRST, and — the security-critical part — decide it WITHOUT running
            // `detect`, because `detect` EXECUTES the installed binary (see [`hold_reason`]). A held
            // component is therefore never spawned and never installed: this `continue` is the only
            // thing standing between a SYSTEM/root beacon and a component that treats every argument
            // as "boot me". (Its bytes are still staged by the catalog-blind worker; see
            // `HeldComponent`.)
            if let Some(reason) = hold_reason(target) {
                held.push(HeldComponent {
                    name: component.name.clone(),
                    reason,
                });
                continue;
            }

            // Then choose the EVIDENCE, again from the declaration alone. `detect` is reached only
            // for a component whose declaration permits executing it; a digest-evidenced dest is
            // measured instead, so no exec site in this function can be reached with it.
            //
            // For a digest-evidenced component the measurement is against EVERY variant's digest
            // (dig_ecosystem#1912): a host running the headless build has bytes that hash to the
            // headless digest, not the default's, and that is still "the current build is installed"
            // — so a match on ANY variant is a Skip, and only bytes matching no variant are an
            // Update. All variants of one build share the same manifest version + build number.
            let detected = if target.evidence.requires_execution() {
                detect(&target.dest)
            } else {
                let digests: Vec<&str> = artifacts.iter().map(|a| a.sha256.as_str()).collect();
                digest_evidence_any(&target.dest, &digests, &component.version, digest)
            };

            // The worker-reported `staged_path` of EACH variant is carried verbatim here and is NOT
            // trusted: it is canonicalized + confined to the broker-owned staging dir by
            // [`crate::install::contained_staged_path`] at install time (SPEC §8.3), before any byte
            // is read. Keeping planning pure of filesystem I/O leaves that guard at the single point
            // where the bytes are actually hashed + installed. The default variant is first, so the
            // applier's loadability selection prefers it (dig_ecosystem#1912).
            let mut variants = Vec::with_capacity(artifacts.len());
            for artifact in &artifacts {
                let staged_path = staged
                    .iter()
                    .find(|s| {
                        s.component == component.name
                            && s.os == platform.os
                            && s.arch == platform.arch
                            && s.variant == artifact.variant
                    })
                    .map(|s| PathBuf::from(&s.staged_path))
                    .ok_or_else(|| BrokerError::StagedArtifactMissing {
                        component: component.name.clone(),
                        os: platform.os.clone(),
                        arch: platform.arch.clone(),
                    })?;
                variants.push(PlannedVariant {
                    variant: artifact.variant.clone(),
                    expected_digest: artifact.sha256.clone(),
                    staged_path,
                });
            }

            let installed_build = installed_build(&detected);
            let decision = decide(&detected, &component.version);
            // #666 F3: the enumeration decision must key on the WHOLE binary set, not just the
            // primary `dest`. A prior pass may have advanced the primary but left an alias stale
            // (a transient alias lock → the component reported `Deferred` with primary-new/alias-old,
            // no rollback). If we keyed only on the primary here, we would see it current → `Skip` →
            // the stale alias would NEVER be re-refreshed and Bug A would recur. So: when the primary
            // says `Skip` but ANY alias is missing or reports a different version, re-drive the
            // component as an `Update` so the applier refreshes + health-checks the whole set.
            // The alias re-drive probes each alias, so it is reachable only for a component the
            // declaration permits executing. A digest-evidenced component declares no aliases (or it
            // was held above), so there is nothing for it to re-drive either way.
            let (action, summary) = if target.evidence.requires_execution() {
                redrive_for_stale_alias(
                    target,
                    &component.version,
                    decision.action,
                    decision.summary,
                    detect,
                )
            } else {
                // dig_ecosystem#1858: only the NON-probe path needs the build-monotonicity guard.
                // A probe reports a version the shared matrix can compare directly, so a host ahead
                // of the feed is already decided `Skip` there; a digest can only say "these are not
                // the promised bytes", which reads identically for a newer build and an older one.
                // Scoping the guard here — rather than over both paths — also keeps it clear of
                // `redrive_for_stale_alias`, whose deliberate `Skip → Update` escalation exists to
                // refresh a stale ALIAS (#666 Bug A) and must not be undone.
                guard_newer_installed(
                    decision.action,
                    decision.summary,
                    recorded.build_of(&component.name),
                    component.build,
                )
            };
            components.push(PlannedComponent {
                name: component.name.clone(),
                method: target.method,
                dest: target.dest.clone(),
                aliases: target.aliases.clone(),
                version: component.version.clone(),
                build: component.build,
                variants,
                action,
                summary,
                installed_build,
                evidence: target.evidence,
            });
        }
        Ok(Self { components, held })
    }

    // (see PlannedComponent below for the per-component variant accessors)

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
/// The version is the FIRST whitespace-separated token that packs, not the last. A `--version` line
/// is conventionally `<program> <version>` (clap's default), but trailing detail is common
/// (`dig-app 3.4.0 (build abc123)`) — and taking the last token there yields `(build`, which packs to
/// nothing. Reading "the first token that IS a version" is stable against detail appearing on either
/// side, so a cosmetic change to a component's version line cannot silently un-age its install.
#[must_use]
fn installed_build(detected: &DetectedVersion) -> Option<u64> {
    match detected {
        DetectedVersion::Present(raw) => raw.split_whitespace().find_map(pack_build),
        DetectedVersion::Absent => None,
    }
}

/// Establish an [`VersionEvidence::ArtifactDigest`] component's installed version by MEASURING the
/// file at `dest` against the signed manifest artifact's `expected_digest` — never by running it.
///
/// The answer is expressed as a [`DetectedVersion`] so it flows into the SAME shared decision matrix
/// ([`decide`]) every other component uses; there is no second Install/Update/Skip matrix to keep in
/// agreement with the first (SPEC §12).
///
/// - digest MATCHES → the current build is what is installed, so report the manifest's own version.
///   This is exact rather than optimistic: for a raw-binary component the verified artifact is
///   renamed into `dest`, so equal bytes mean equal build.
/// - digest DIFFERS → *something* is installed but its build is not established. Reported as a
///   present-but-unreadable version, which the shared matrix turns into an Update and which leaves
///   the component deliberately UN-AGEABLE (`installed_build == None`). That is the conservative
///   direction: a cross-pass rollback then refuses the anti-downgrade floor gate rather than
///   reinstating bytes whose build nobody can bound.
/// - NO digest (absent, unreadable, a refused symlink) → nothing is established there → Install.
#[must_use]
fn digest_evidence_any(
    dest: &Path,
    expected_digests: &[&str],
    manifest_version: &str,
    digest: &DigestReader,
) -> DetectedVersion {
    match digest(dest) {
        None => DetectedVersion::Absent,
        // A match on ANY variant's digest is "the current build is installed" (dig_ecosystem#1912):
        // a headless host runs bytes that hash to the headless variant, not the default, and that is
        // still current. All variants share the manifest version, so the answer is the same either way.
        Some(found) if expected_digests.iter().any(|d| found.eq_ignore_ascii_case(d)) => {
            DetectedVersion::Present(manifest_version.to_string())
        }
        Some(_) => DetectedVersion::Present(String::new()),
    }
}

/// Why `target` is HELD this pass, or `None` to plan it normally ([`VersionEvidence`]).
///
/// Takes ONLY the target: the decision is deliberately made from the DECLARATION, without touching —
/// let alone executing — the binary. Reading the answer first would defeat the purpose, since the
/// read IS the exec (see [`VersionEvidence`]).
///
/// The reason states the cause and the remedy, so a held pass says why the component was left alone
/// rather than reporting a component-shaped silence. `dest.exists()` — a metadata read, no exec —
/// only sharpens that wording.
#[must_use]
fn hold_reason(target: &ComponentTarget) -> Option<String> {
    let name = &target.name;
    let dest = target.dest.display();
    match target.evidence {
        VersionEvidence::SafeToProbe => None,
        // Content-digest evidence needs no execution, so there is nothing to hold FROM — unless the
        // component also claims aliases, whose freshness this evidence class says nothing about
        // (an alias is not named in the manifest, so it has no artifact digest of its own). Rather
        // than silently skip the alias check that every other component gets, hold fail-closed.
        VersionEvidence::ArtifactDigest if target.aliases.is_empty() => None,
        VersionEvidence::ArtifactDigest => Some(format!(
            "held: {name} declares content-digest evidence AND {} alias binaries, which this beacon \
             cannot reconcile — an alias carries no manifest artifact digest of its own, so its \
             freshness could only be established by executing it. Nothing was probed, installed or \
             rolled back. Either drop the aliases or give the component a form of evidence that \
             covers them.",
            target.aliases.len()
        )),
        VersionEvidence::UnsafeToProbe => Some(format!(
            "held: {name} {presence} {dest} and is declared unsafe to probe, so the beacon did not \
             run it and cannot tell which version is there. Nothing was probed, downloaded over, \
             installed or rolled back. It updates once it either ships a `--version` that prints and \
             EXITS without starting the app (dig_ecosystem#1749) or is declared to carry \
             content-digest evidence (dig_ecosystem#1803).",
            presence = if target.dest.exists() {
                "is installed at"
            } else {
                "is not installed at"
            }
        )),
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

/// Hold back an update that would move a component BACKWARDS, when this beacon's own record says the
/// build already installed is NEWER than the one the feed offers (dig_ecosystem#1858).
///
/// Needed because a digest-evidenced component's enumeration cannot express "ahead of the feed": the
/// only two answers a hash gives are "these are the promised bytes" and "these are not", and the second
/// reads exactly the same for a newer build as for an older one — so a host running ahead was planned as
/// an Update and pushed backwards. The shared decision matrix lives in the external
/// `dig-release-resolver`, so the correction sits on its OUTPUT, here, where the beacon's own record is.
///
/// **The only transition this may make is `Update → Skip`.** It is a brake, never an accelerator: it can
/// stop an install the resolver asked for, and it can never cause one the resolver did not — so no
/// recorded value, however wrong or stale, can talk the beacon into installing something. An absent
/// record (`None`) leaves the decision untouched, which is how every host starts and how a host with a
/// corrupt record file behaves ([`InstalledBuilds`]).
fn guard_newer_installed(
    action: UpdateAction,
    summary: String,
    recorded_build: Option<u64>,
    manifest_build: u64,
) -> (UpdateAction, String) {
    if action != UpdateAction::Update {
        return (action, summary);
    }
    let Some(recorded) = recorded_build else {
        return (action, summary);
    };
    if recorded <= manifest_build {
        return (action, summary);
    }
    (
        UpdateAction::Skip,
        format!(
            "installed build {recorded} is newer than the feed's {manifest_build} — nothing to do"
        ),
    )
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

    /// The record set of a beacon that has never installed anything — the state every host starts in,
    /// and the one every scenario that is not about build monotonicity (#1858) wants.
    fn nothing_recorded() -> InstalledBuilds {
        InstalledBuilds::default()
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
                    variant: None,
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
            variant: None,
            sha256: "deadbeef".into(),
            size: 1,
            staged_path: path.into(),
        }
    }

    /// A staged artifact carrying a `variant` token, at a distinct path — the dig_ecosystem#1912
    /// shape a headless build stages as.
    fn staged_variant(name: &str, variant: &str, digest: &str, path: &str) -> StagedArtifact {
        StagedArtifact {
            variant: Some(variant.into()),
            sha256: digest.into(),
            staged_path: path.into(),
            ..staged(name, path)
        }
    }

    fn catalog() -> Catalog {
        Catalog::new(vec![ComponentTarget {
            name: "digstore".into(),
            method: InstallMethod::RawBinary,
            dest: PathBuf::from("/opt/dig/digstore"),
            aliases: vec![PathBuf::from("/opt/dig/digs")],
            service: None,
            evidence: VersionEvidence::SafeToProbe,
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
                        variant: None,
                    }],
                })
                .collect(),
            ..manifest_one("unused", "0.0.0", 0, "deadbeef")
        }
    }

    /// The `sha256` every fixture manifest artifact carries — so a digest reader answering THIS means
    /// "the manifest's build is what is installed", and answering anything else is a mismatch.
    const FIXTURE_DIGEST: &str = "deadbeef";

    /// A component name that is neither dig-app nor in the shipped catalog — the stand-in for "some
    /// future component nobody has established evidence for yet". The HELD machinery must stay
    /// covered by such a component now that dig-app has left it: a hold test pinned to dig-app would
    /// have silently stopped testing the hold the moment dig-app moved to digest evidence.
    const FUTURE_UNKNOWN_COMPONENT: &str = "dig-future-tray-app";

    /// An ordinary alias-less component that answers `--version`.
    fn probeable(name: &str, dest: &str) -> ComponentTarget {
        ComponentTarget {
            name: name.into(),
            method: InstallMethod::RawBinary,
            dest: PathBuf::from(dest),
            aliases: vec![],
            service: None,
            evidence: VersionEvidence::SafeToProbe,
        }
    }

    /// A catalog holding `digstore` (an ordinary component that answers `--version`) beside
    /// `dig-app` (content-digest evidenced, so the beacon must never execute it).
    fn catalog_with_dig_app() -> Catalog {
        Catalog::new(vec![
            probeable("digstore", "/opt/dig/digstore"),
            ComponentTarget {
                name: DIG_APP_COMPONENT_NAME.into(),
                method: InstallMethod::RawBinary,
                dest: PathBuf::from("/opt/dig/dig-app"),
                aliases: vec![],
                service: None,
                evidence: VersionEvidence::ArtifactDigest,
            },
        ])
    }

    /// A catalog holding `digstore` beside a component declared [`VersionEvidence::UnsafeToProbe`] —
    /// the fail-closed default, kept under test independently of dig-app.
    fn catalog_with_an_unevidenced_component() -> Catalog {
        Catalog::new(vec![
            probeable("digstore", "/opt/dig/digstore"),
            ComponentTarget {
                name: FUTURE_UNKNOWN_COMPONENT.into(),
                method: InstallMethod::RawBinary,
                dest: PathBuf::from("/opt/dig").join(FUTURE_UNKNOWN_COMPONENT),
                aliases: vec![],
                service: None,
                evidence: VersionEvidence::UnsafeToProbe,
            },
        ])
    }

    /// A digest reader that PANICS if consulted — the control for every probe-path fixture. It keeps
    /// the two evidence classes genuinely separate: a planner that hashed every destination "just in
    /// case" would do pointless privileged I/O over binaries whose version it already asked for, and
    /// a reader that merely returned `None` could not tell that apart from not being called.
    fn digest_reader_that_must_not_be_consulted(path: &Path) -> Option<String> {
        panic!(
            "the planner hashed {} — a component that answers `--version` is established by its \
             probe, not by measuring it",
            path.display()
        )
    }

    /// A digest reader answering `hex` for EVERY path (`None` = nothing readable installed there).
    fn digest_reader(hex: Option<&str>) -> impl Fn(&Path) -> Option<String> + '_ {
        move |_: &Path| hex.map(str::to_string)
    }

    /// A probe that answers honestly for `digstore` and PANICS if asked about ANY other destination.
    ///
    /// In production `detect` is not a lookup — it is `Command::new(dest).arg("--version")` run by a
    /// SYSTEM/root beacon, and for dig-app <= 3.3.0 that boots the identity agent, seals a master
    /// seed and binds a signing socket. So "was the probe called?" IS the security property, and a
    /// probe that merely returns a mute answer cannot express it: such a fixture passes whether or
    /// not the exec happened. Panicking makes the exec observable. digstore stays a truthful control,
    /// so a passing test also proves the planner still probes what it IS allowed to probe.
    ///
    /// It ALLOW-LISTS the one destination it may answer for rather than rejecting dig-app by name,
    /// which is what keeps it a gate: a component added to a fixture later is refused by default
    /// instead of quietly inheriting permission to be executed at machine privilege.
    fn probe_that_may_only_run_digstore(path: &Path) -> DetectedVersion {
        assert!(
            path.ends_with("digstore"),
            "the planner EXECUTED {} — the privileged exec the evidence declaration exists to \
             prevent (a SYSTEM boot of an installed binary on every pass)",
            path.display()
        );
        DetectedVersion::Present("digstore 0.14.0".into())
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
    fn every_component_the_beacon_may_execute_is_named_here_explicitly() {
        // The question this answers is "which components may a SYSTEM/root beacon EXECUTE?", so it is
        // asked of the WHOLE catalog rather than of four names: a component added later is unnamed
        // here, so declaring it `SafeToProbe` fails this test until someone deliberately adds it and
        // states why. A by-name loop would let the sixth component inherit permission in silence.
        const MAY_BE_EXECUTED: [&str; 4] = [
            // Each of these ships a CLI entrypoint whose `--version` prints and exits; verified by
            // execution under the cleared probe environment (all four answered in under a second).
            "dig-node",
            "digstore",
            "dig-dns",
            BEACON_COMPONENT_NAME,
        ];
        let cat = Catalog::alpha_defaults_in(Path::new("/opt/dig/bin"), &platform());

        let mut seen = 0;
        for target in cat.targets() {
            seen += 1;
            let may_execute = MAY_BE_EXECUTED.contains(&target.name.as_str());
            assert_eq!(
                target.evidence.requires_execution(), may_execute,
                "{} is declared {:?}; a component the beacon may execute at machine privilege must be named in MAY_BE_EXECUTED with a reason, and everything else must be established without running it",
                target.name, target.evidence
            );
        }
        assert_eq!(
            seen,
            MAY_BE_EXECUTED.len() + 1,
            "the catalog should hold the executable set plus dig-app; if that changed, the new component's evidence declaration needs reviewing here"
        );
        assert!(
            !MAY_BE_EXECUTED.contains(&DIG_APP_COMPONENT_NAME),
            "dig-app must never join the executable set: it boots its identity agent on any argument, \
             and the 3.3.0-or-older population that does so is real and unobservable"
        );
        assert_eq!(
            cat.target(DIG_APP_COMPONENT_NAME).unwrap().evidence,
            VersionEvidence::ArtifactDigest,
            "dig-app is kept current by MEASURING it against the signed manifest, never by running it"
        );
    }

    #[test]
    fn a_digest_evidenced_component_is_planned_without_ever_being_executed() {
        // dig_ecosystem#1803, THE CORE PROPERTY. dig-app's installed build is established by hashing
        // its destination against the signed manifest artifact's `sha256`, so it is planned like any
        // other component — reaching `plan.components`, never `plan.held` — while NEVER being run.
        //
        // The fixture is built so a WRONG PLACEMENT of the digest branch cannot pass. Asserting only
        // "dig-app is planned as Skip" would also hold for an implementation that probed first and
        // then overrode the answer with the digest; the panicking probe is what distinguishes those,
        // because it makes the exec itself observable rather than only its effect on the outcome.
        // digstore stays a TRUTHFUL control on 0.14.0 against a 0.15.0 manifest, so the same run also
        // proves the planner still probes what it IS allowed to probe — a fixture in which every
        // component were digest-evidenced could not see a probe path that had stopped working.
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
            &probe_that_may_only_run_digstore,
            &digest_reader(Some(FIXTURE_DIGEST)),
            &nothing_recorded(),
        )
        .unwrap();

        assert!(
            plan.held.is_empty(),
            "content-digest evidence needs no execution, so there is nothing to hold from: {:?}",
            plan.held
        );
        let dig_app = plan
            .components
            .iter()
            .find(|c| c.name == DIG_APP_COMPONENT_NAME)
            .expect("dig-app is PLANNED now, not held (dig_ecosystem#1803)");
        assert_eq!(
            dig_app.action,
            UpdateAction::Skip,
            "the installed bytes hash to the manifest artifact's digest, so the current build IS \
             installed: {}",
            dig_app.summary
        );
        assert_eq!(
            dig_app.installed_build,
            Some(3_004_000),
            "a digest match ages the install on the same packed scale as every other component"
        );
        assert_eq!(
            dig_app.evidence,
            VersionEvidence::ArtifactDigest,
            "the evidence class must reach the applier, or its health gate would fall back to a probe"
        );

        let digstore = plan
            .components
            .iter()
            .find(|c| c.name == "digstore")
            .expect("the control component is still planned");
        assert_eq!(
            digstore.action,
            UpdateAction::Update,
            "the probe path must keep working: digstore is on 0.14.0 against a 0.15.0 manifest"
        );
    }

    #[test]
    fn a_digest_mismatch_plans_an_update_and_leaves_the_install_unageable() {
        // The mismatch arm. SOMETHING is installed but its build is not established, so the shared
        // matrix must reinstall the verified artifact — and `installed_build` must stay `None`, which
        // is what makes a cross-pass rollback refuse the anti-downgrade floor rather than reinstate
        // bytes whose age nobody can bound. The digest differs from the manifest's by ONE nibble, so
        // the test cannot pass on a comparison that only checks the length or the prefix.
        let m = manifest_of(&[("dig-app", "3.4.0", 3_004_000)]);
        let plan = Plan::build(
            &m,
            &[staged("dig-app", "/staging/dig-app")],
            &catalog_with_dig_app(),
            &platform(),
            &|path| {
                panic!(
                    "the planner executed {} to establish a version",
                    path.display()
                )
            },
            &digest_reader(Some("deadbeee")),
            &nothing_recorded(),
        )
        .unwrap();

        assert_eq!(plan.components[0].action, UpdateAction::Update);
        assert_eq!(
            plan.components[0].installed_build, None,
            "an unestablished build must be UN-AGEABLE, so a rollback declines rather than guesses"
        );
    }

    #[test]
    fn a_digest_match_is_case_insensitive_across_the_manifests_hex_casing() {
        // The digest is hex, and hex casing is not semantically meaningful. A case-sensitive compare
        // would report a spurious mismatch — reinstalling a perfectly current dig-app on EVERY pass,
        // which is the failure mode that looks like success in a report.
        let m = manifest_one("dig-app", "3.4.0", 3_004_000, "DEADBEEF");
        let plan = Plan::build(
            &m,
            &[staged("dig-app", "/staging/dig-app")],
            &catalog_with_dig_app(),
            &platform(),
            &|path| {
                panic!(
                    "the planner executed {} to establish a version",
                    path.display()
                )
            },
            &digest_reader(Some("deadbeef")),
            &nothing_recorded(),
        )
        .unwrap();
        assert_eq!(plan.components[0].action, UpdateAction::Skip);
    }

    #[test]
    fn an_absent_digest_evidenced_component_is_planned_install() {
        // The absent arm: no readable file at the destination — which also covers an unreadable one
        // and a refused symlink, since the reader collapses all three to `None`. Nothing is
        // established there, so the component is INSTALLED rather than held or skipped.
        let m = manifest_of(&[("dig-app", "3.4.0", 3_004_000)]);
        let plan = Plan::build(
            &m,
            &[staged("dig-app", "/staging/dig-app")],
            &catalog_with_dig_app(),
            &platform(),
            &|path| {
                panic!(
                    "the planner executed {} to establish a version",
                    path.display()
                )
            },
            &digest_reader(None),
            &nothing_recorded(),
        )
        .unwrap();
        assert_eq!(plan.components[0].action, UpdateAction::Install);
        assert_eq!(plan.components[0].installed_build, None);
    }

    /// The digest of the DEFAULT dig-app build in these fixtures, and the digest of the HEADLESS one
    /// — genuinely different, so a match on one is not a match on the other.
    const DEFAULT_DIGEST: &str = "deadbeef";
    const HEADLESS_DIGEST: &str = "feedface";

    /// A dig-app manifest carrying BOTH linux/x64 builds — the default and the headless variant.
    fn manifest_dig_app_two_variants() -> Manifest {
        let mut m = manifest_one("dig-app", "3.5.0", 3_005_000, DEFAULT_DIGEST);
        m.components[0].artifacts.push(Artifact {
            os: "linux".into(),
            arch: "x64".into(),
            url: "https://x/headless".into(),
            sha256: HEADLESS_DIGEST.into(),
            size: 1,
            variant: Some("headless".into()),
        });
        m
    }

    #[test]
    fn a_multi_variant_component_plans_all_variants_default_first() {
        // dig_ecosystem#1912: both linux/x64 builds must reach the applier as PlannedVariants, the
        // default first (so selection prefers it), each carrying its OWN digest + staged path.
        let m = manifest_dig_app_two_variants();
        let plan = Plan::build(
            &m,
            &[
                staged("dig-app", "/staging/dig-app"),
                staged_variant("dig-app", "headless", HEADLESS_DIGEST, "/staging/dig-app-headless"),
            ],
            &catalog_with_dig_app(),
            &platform(),
            &|path| panic!("the planner executed {} for a version", path.display()),
            // The host has NEITHER build installed, so the component is a fresh Install.
            &digest_reader(None),
            &nothing_recorded(),
        )
        .unwrap();

        let dig_app = &plan.components[0];
        assert_eq!(dig_app.variants.len(), 2, "both builds are planned");
        assert_eq!(dig_app.variants[0].variant, None, "the default is first");
        assert_eq!(dig_app.variants[0].expected_digest, DEFAULT_DIGEST);
        assert_eq!(dig_app.variants[0].staged_path, PathBuf::from("/staging/dig-app"));
        assert_eq!(dig_app.variants[1].variant.as_deref(), Some("headless"));
        assert_eq!(dig_app.variants[1].expected_digest, HEADLESS_DIGEST);
        assert_eq!(
            dig_app.variants[1].staged_path,
            PathBuf::from("/staging/dig-app-headless")
        );
        assert_eq!(dig_app.action, UpdateAction::Install);
    }

    #[test]
    fn a_host_running_the_headless_build_is_current_not_reinstalled_every_pass() {
        // The digest-evidence enumeration must recognise the host as CURRENT when its bytes hash to
        // ANY variant's digest — here the HEADLESS one (dig_ecosystem#1912). Keying only on the
        // default digest would report the headless host as an Update and reinstall it on every pass —
        // the "success" that is really a churn loop. The reader returns the headless digest, which is
        // NOT the default, so a default-only comparison would fail this.
        let m = manifest_dig_app_two_variants();
        let plan = Plan::build(
            &m,
            &[
                staged("dig-app", "/staging/dig-app"),
                staged_variant("dig-app", "headless", HEADLESS_DIGEST, "/staging/dig-app-headless"),
            ],
            &catalog_with_dig_app(),
            &platform(),
            &|path| panic!("the planner executed {} for a version", path.display()),
            &digest_reader(Some(HEADLESS_DIGEST)),
            &nothing_recorded(),
        )
        .unwrap();
        assert_eq!(
            plan.components[0].action,
            UpdateAction::Skip,
            "a host whose bytes hash to the headless variant is on the current build"
        );
        assert_eq!(
            plan.components[0].installed_build,
            Some(3_005_000),
            "and the install is aged on the same scale"
        );
    }

    #[test]
    fn a_digest_evidenced_component_that_claims_aliases_is_held_fail_closed() {
        // Content-digest evidence says nothing about an ALIAS: an alias is not named in the manifest,
        // so it carries no artifact digest of its own, and its freshness could only be established by
        // running it. Rather than silently skip the alias check every other component gets — which
        // would let an alias sit frozen at its install-time build while the pass reported success
        // (the #666 Bug A shape) — such a declaration is HELD.
        //
        // This is asserted rather than left to a "dig-app happens to declare no aliases" test, because
        // the latter pins today's catalog instead of the rule a future component would be added under.
        let m = manifest_of(&[("dig-app", "3.4.0", 3_004_000)]);
        let with_alias = Catalog::new(vec![ComponentTarget {
            name: DIG_APP_COMPONENT_NAME.into(),
            method: InstallMethod::RawBinary,
            dest: PathBuf::from("/opt/dig/dig-app"),
            aliases: vec![PathBuf::from("/opt/dig/dig-app-alias")],
            service: None,
            evidence: VersionEvidence::ArtifactDigest,
        }]);
        let plan = Plan::build(
            &m,
            &[staged("dig-app", "/staging/dig-app")],
            &with_alias,
            &platform(),
            &|path| panic!("the planner executed {}", path.display()),
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
        )
        .expect("an unreconcilable declaration is a hold, not a failed plan");

        assert!(plan.components.is_empty());
        assert_eq!(plan.held.len(), 1);
        assert!(
            plan.held[0].reason.contains("alias"),
            "the hold must name the alias as its cause: {}",
            plan.held[0].reason
        );
    }

    #[test]
    fn an_unsafe_to_probe_component_is_held_while_its_siblings_still_update() {
        // The fail-closed core (dig_ecosystem#1746/#1749) AND the security property in one fixture,
        // now carried by a SYNTHETIC component rather than by dig-app: the hold is the default every
        // component added later inherits, so it must stay under test after dig-app moved to digest
        // evidence. It is declared unsafe to probe, so it is HELD **without ever being executed** —
        // the probe panics if asked about it — and gets no plan entry, hence nothing the applier could
        // install, health-gate or roll back. digstore, the truthful control, is on 0.14.0 against a
        // 0.15.0 manifest and MUST still be probed and planned as an Update: holding one component
        // must neither abandon the pass nor stop the beacon probing what it may.
        let m = manifest_of(&[
            ("digstore", "0.15.0", 15_000),
            (FUTURE_UNKNOWN_COMPONENT, "1.0.0", 1_000_000),
        ]);
        let plan = Plan::build(
            &m,
            &[
                staged("digstore", "/staging/digstore"),
                staged(FUTURE_UNKNOWN_COMPONENT, "/staging/future"),
            ],
            &catalog_with_an_unevidenced_component(),
            &platform(),
            &probe_that_may_only_run_digstore,
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
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
            .find(|h| h.name == FUTURE_UNKNOWN_COMPONENT)
            .expect("an unevidenced component is reported as HELD, never silently omitted");
        assert!(
            held.reason.contains("--version"),
            "the hold must name its cause so a pass is never a vacuous success: {}",
            held.reason
        );
    }

    #[test]
    fn an_unsafe_to_probe_component_is_never_executed_even_to_decide_the_hold() {
        // THE SECURITY PROPERTY, isolated. The unsafe component is the ONLY one in the manifest, so
        // nothing else could account for a probe call: any exec at all fails this test. A hold
        // decided from the probe's ANSWER — however correct its outcome — cannot pass here, which is
        // exactly the point: that answer is unobtainable without the exec. The digest reader panics
        // too, so a hold must be decided from the DECLARATION and nothing else.
        let m = manifest_of(&[(FUTURE_UNKNOWN_COMPONENT, "1.0.0", 1_000_000)]);
        let plan = Plan::build(
            &m,
            &[staged(FUTURE_UNKNOWN_COMPONENT, "/staging/future")],
            &catalog_with_an_unevidenced_component(),
            &platform(),
            &|path| panic!("the planner executed {} to decide a hold", path.display()),
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
        )
        .expect("holding a component never fails the plan");

        assert!(plan.components.is_empty());
        assert_eq!(plan.held.len(), 1);
        assert!(
            plan.held[0].reason.contains("did not run it"),
            "the reason must state that the binary was NOT executed: {}",
            plan.held[0].reason
        );
    }

    #[test]
    fn the_evidence_class_drives_the_plan_by_declaration_not_by_component_name() {
        // The whole mechanism must be declaration-driven: an implementation that special-cased dig-app
        // BY NAME — the shortcut a "just make dig-app work" change invites — would fail this, because
        // here dig-app is declared safe to probe and must then be probed and aged like any CLI.
        let m = manifest_of(&[("dig-app", "3.4.0", 3_004_000)]);
        let safe_dig_app = Catalog::new(vec![probeable("dig-app", "/opt/dig/dig-app")]);
        let plan = Plan::build(
            &m,
            &[staged("dig-app", "/staging/dig-app")],
            &safe_dig_app,
            &platform(),
            &|_| DetectedVersion::Present("dig-app 3.3.0".into()),
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
        )
        .unwrap();
        assert!(
            plan.held.is_empty(),
            "a safe-to-probe component is not held"
        );
        assert_eq!(plan.components[0].action, UpdateAction::Update);
        assert_eq!(
            plan.components[0].installed_build,
            Some(3_003_000),
            "and it is aged on the same packed scale as every other component"
        );
    }

    #[test]
    fn a_version_line_with_trailing_detail_is_still_aged_correctly() {
        // A hold must never be reachable by a COSMETIC change to a component's version line. Reading
        // the last whitespace token would take `(build` out of `dig-app 3.4.0 (build abc123)` and pack
        // it to nothing — silently un-ageing a perfectly good install, and for a safe-to-probe
        // component silently reinstalling it every pass. The first token that IS a version is stable
        // against detail on either side.
        let detailed = DetectedVersion::Present("dig-app 3.4.0 (build abc123)".into());
        assert_eq!(installed_build(&detailed), Some(3_004_000));
        assert_eq!(
            installed_build(&DetectedVersion::Present("digstore 0.15.0".into())),
            Some(15_000),
            "the conventional two-token line is unchanged"
        );
        assert_eq!(
            installed_build(&DetectedVersion::Present("0.15.0".into())),
            Some(15_000),
            "a bare version is unchanged"
        );
        assert_eq!(
            installed_build(&DetectedVersion::Present("no version here at all".into())),
            None,
            "and a line with no version in it is still un-ageable"
        );
    }

    #[test]
    fn an_unreadable_version_still_reinstalls_a_safe_to_probe_component() {
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
            &digest_reader(Some(FIXTURE_DIGEST)),
            &nothing_recorded(),
        )
        .unwrap();
        assert!(plan.held.is_empty());
        assert_eq!(plan.components[0].action, UpdateAction::Update);
    }

    #[test]
    fn a_held_component_does_not_need_a_staged_artifact() {
        // The hold is decided BEFORE the staged-artifact lookup, because a component that will not be
        // installed needs no bytes. Deciding it after would make a missing download fault the whole
        // pass (`StagedArtifactMissing`) over a component nobody was going to touch.
        let m = manifest_of(&[(FUTURE_UNKNOWN_COMPONENT, "1.0.0", 1_000_000)]);
        let plan = Plan::build(
            &m,
            &[],
            &catalog_with_an_unevidenced_component(),
            &platform(),
            &|_| panic!("a held component is neither probed nor staged"),
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
        )
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
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
        )
        .unwrap();
        assert_eq!(plan.components.len(), 1);
        assert_eq!(plan.components[0].action, UpdateAction::Install);
        assert_eq!(plan.components[0].primary().expected_digest, "deadbeef");
        assert_eq!(plan.components[0].variants.len(), 1);
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
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
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
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
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
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
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
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
        )
        .unwrap();
        assert_eq!(plan.components[0].action, UpdateAction::Skip);
    }

    #[test]
    fn untracked_component_is_skipped_entirely() {
        let m = manifest_one("some-future-tool", "1.0.0", 1_000_000, "deadbeef");
        let plan = Plan::build(
            &m,
            &[],
            &catalog(),
            &platform(),
            &|_| DetectedVersion::Absent,
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
        )
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
        let err = Plan::build(
            &m,
            &[],
            &catalog(),
            &platform(),
            &|_| DetectedVersion::Absent,
            &digest_reader_that_must_not_be_consulted,
            &nothing_recorded(),
        )
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
    // ===== dig_ecosystem#1858: an installed build NEWER than the feed's is not an update =====

    #[test]
    fn guard_forces_skip_when_the_recorded_build_exceeds_the_manifest_build() {
        // The load-bearing #1858 case: this beacon installed 3.5.0 and the feed now offers 3.4.0. The
        // digest differs, so the resolver said Update — which would install the OLDER build over the
        // newer one. The guard converts exactly that into a Skip.
        let (action, summary) = guard_newer_installed(
            UpdateAction::Update,
            "v3.4.0 (update)".to_string(),
            Some(3_005_000),
            3_004_000,
        );
        assert_eq!(action, UpdateAction::Skip);
        assert!(
            summary.contains("3005000") && summary.contains("3004000"),
            "the summary must state BOTH builds so the skip is auditable: {summary}"
        );
    }

    #[test]
    fn guard_leaves_an_equal_or_lower_recorded_build_alone() {
        // At the bound (equal) and below it, the resolver's Update must survive untouched — the
        // ordinary case, and the one a `>=` comparison would silently break by refusing every
        // re-install of the SAME build (the digest-mismatch repair path).
        for recorded in [3_004_000u64, 3_003_000, 0] {
            let (action, summary) = guard_newer_installed(
                UpdateAction::Update,
                "v3.4.0 (update)".to_string(),
                Some(recorded),
                3_004_000,
            );
            assert_eq!(
                action,
                UpdateAction::Update,
                "recorded {recorded} is not newer than 3004000, so the update stands"
            );
            assert_eq!(summary, "v3.4.0 (update)", "and its summary is untouched");
        }
    }

    #[test]
    fn guard_never_turns_a_skip_into_an_update() {
        // The guard is a BRAKE, never an accelerator. Across every (action, recorded) combination it
        // may only ever produce `Update -> Skip`; no recorded value — absent, stale, lower, higher —
        // may cause an install the resolver did not already ask for.
        for action in [
            UpdateAction::Skip,
            UpdateAction::Install,
            UpdateAction::Update,
        ] {
            for recorded in [None, Some(0u64), Some(3_004_000), Some(u64::MAX)] {
                let (out, _) = guard_newer_installed(action, "s".to_string(), recorded, 3_004_000);
                let legal =
                    out == action || (action == UpdateAction::Update && out == UpdateAction::Skip);
                assert!(
                    legal,
                    "{action:?} with recorded {recorded:?} became {out:?} — the only legal \
                     transition is Update -> Skip"
                );
            }
        }
    }

    #[test]
    fn the_recorded_build_is_never_consulted_to_permit_an_install() {
        // Stated from the other side: an Install/Skip decision is returned VERBATIM, summary included,
        // whatever the record says. A guard that could rewrite those would be able to install bytes
        // the resolver had judged unnecessary, on the strength of a local, unsigned file.
        for action in [UpdateAction::Install, UpdateAction::Skip] {
            let (out, summary) =
                guard_newer_installed(action, "verbatim".to_string(), Some(u64::MAX), 3_004_000);
            assert_eq!(out, action);
            assert_eq!(summary, "verbatim");
        }
    }

    #[test]
    fn a_digest_evidenced_component_recorded_newer_than_the_feed_is_planned_skip() {
        // #1858 end to end through `Plan::build`, with dig-app's real evidence class. The digest on
        // disk does NOT match the manifest's (so enumeration alone yields Update — the pre-fix
        // behaviour), the beacon's own record says 3.5.0 is installed, and the feed offers 3.4.0.
        //
        // digstore stays a TRUTHFUL control on 0.14.0 against a 0.15.0 manifest with NOTHING recorded,
        // so the same run proves the guard did not simply stop the planner updating things.
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
            &probe_that_may_only_run_digstore,
            &digest_reader(Some("00000000")),
            &InstalledBuilds::from_pairs([("dig-app", 3_005_000u64)]),
        )
        .unwrap();

        let dig_app = plan
            .components
            .iter()
            .find(|c| c.name == DIG_APP_COMPONENT_NAME)
            .expect("dig-app is planned, not held");
        assert_eq!(
            dig_app.action,
            UpdateAction::Skip,
            "the host is AHEAD of the feed; installing would be a downgrade: {}",
            dig_app.summary
        );
        let digstore = plan
            .components
            .iter()
            .find(|c| c.name == "digstore")
            .expect("the control component is still planned");
        assert_eq!(
            digstore.action,
            UpdateAction::Update,
            "the control must still update — the guard is per-component, not a global brake"
        );
    }

    #[test]
    fn an_absent_record_plans_a_digest_evidenced_component_exactly_as_before() {
        // The no-record baseline: with nothing recorded, a digest mismatch still plans an Update, so
        // the guard cannot have made a fresh host stop updating.
        let m = manifest_of(&[("dig-app", "3.4.0", 3_004_000)]);
        let plan = Plan::build(
            &m,
            &[staged("dig-app", "/staging/dig-app")],
            &catalog_with_dig_app(),
            &platform(),
            &probe_that_may_only_run_digstore,
            &digest_reader(Some("00000000")),
            &nothing_recorded(),
        )
        .unwrap();
        assert_eq!(plan.components[0].action, UpdateAction::Update);
    }
}
