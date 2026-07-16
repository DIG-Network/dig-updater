//! Applying one verified plan — the privileged core of an update pass (SPEC §9, §9.5).
//!
//! [`Installer::apply`] takes the plan the (unprivileged) worker returned and turns it into
//! installs, in this fixed order:
//!
//! 1. **Independent re-verify (SPEC §8.3).** The worker's word is never trusted on the install
//!    path: the broker re-parses the raw signed feed the worker returned and re-runs the WHOLE
//!    trust chain — delegation + manifest signatures, freshness, anti-downgrade floor — under its
//!    OWN pinned root key and the persisted trust state. A compromised or buggy worker cannot
//!    fabricate a plan that survives this, because it holds no key that chains to the pinned root.
//! 2. **Enumerate + plan.** Against the RE-VERIFIED manifest (the authority), decide Install /
//!    Update / Skip per tracked component ([`crate::plan`]).
//! 3. **Apply every OTHER component behind the health gate.** For each actionable component
//!    except the beacon's own ([`BEACON_COMPONENT_NAME`]): refuse a staged path that escapes the
//!    broker-owned staging dir, copy the staged bytes ONCE into a broker-private file while
//!    hashing them against the re-verified digest (so the hashed bytes are the installed bytes —
//!    the reverify→install TOCTOU is closed by construction), snapshot the current binary for
//!    rollback, install per-OS from the private copy, then health-probe — rolling back
//!    (re-verified, floor-bounded) on failure.
//! 4. **Advance state.** The monotonic trust state advances ONLY if every OTHER actionable
//!    component installed AND passed its health gate (SPEC §9 step 7) — never on a partial or
//!    failed pass, and never before the state directory is hardened.
//! 5. **Self-update, always LAST (SPEC §8.1, #504-F).** If the beacon's OWN component is
//!    actionable, [`Installer::apply_one_self`] runs it through the identical stage → snapshot →
//!    install → health → rollback skeleton as step 3 — but only now, once every other component
//!    has already settled, and via [`crate::selfupdate`]'s platform-specific swap in place of the
//!    generic per-OS installer. Applying it any earlier would risk leaving another component's
//!    in-flight install inconsistent if this process died mid-self-replace; applying it last costs
//!    nothing, because the transient process model (SPEC §8.1) means this pass exits right after.

use std::path::Path;

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use dig_release_resolver::{DetectedVersion, UpdateAction};
use dig_updater_trust::{
    verify_update_chain, Manifest, SignedDelegation, SignedManifest, TrustError, TrustState,
};
use dig_updater_worker::{Platform, VerifiedPlan, WorkerReport};

use crate::error::BrokerError;
use crate::health::{check_health, VersionProbe};
use crate::install::{
    contained_staged_path, install_from_private, private_target, stage_and_verify_private,
    InstallOutcome, RetryPolicy,
};
use crate::plan::{Catalog, InstallMethod, Plan, PlannedComponent, BEACON_COMPONENT_NAME};
use crate::rollback::{LkgCache, LkgEntry, RestoreKind};
use crate::secure::harden_state_dir;
use crate::selfupdate::apply_self_update;
use crate::service::{ServiceAction, ServiceControl};
use crate::state::{LoadedState, TrustStateStore};

/// What one component's apply produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentResult {
    /// The component was installed and passed its health gate.
    Installed,
    /// Already current — left untouched.
    Skipped,
    /// The target was locked; the install deferred to the next pass.
    Deferred,
    /// The install failed (or failed health) and was rolled back to the last-known-good build.
    RolledBack,
}

impl ComponentResult {
    /// The stable, machine-classifiable token for this result (`installed` / `skipped` /
    /// `deferred` / `rolled_back`) — the SAME snake_case this type's `Serialize` impl emits, so a
    /// consumer that reads it off a rendered [`ComponentOutcome`] (e.g. the unprivileged
    /// [`crate::status::StatusSnapshot`] mirror) never drifts from the JSON contract.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Skipped => "skipped",
            Self::Deferred => "deferred",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// The per-component result line of a [`PassReport`] — agent-consumable (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentOutcome {
    /// The component name.
    pub component: String,
    /// The planned action (`install` / `update` / `skip`).
    pub action: String,
    /// What actually happened.
    pub result: ComponentResult,
    /// A human-readable detail. For [`ComponentResult::Installed`] this is the version the health
    /// gate ACTUALLY re-observed on disk after installing (#582) — verified reality, never the
    /// plan's pre-install prediction ([`PlannedComponent::summary`](crate::plan::PlannedComponent)).
    /// Every other result carries the plan summary or a failure reason, neither of which claims to
    /// describe a post-install state.
    pub detail: String,
}

impl ComponentOutcome {
    fn from(pc: &PlannedComponent, result: ComponentResult, detail: String) -> Self {
        Self {
            component: pc.name.clone(),
            action: pc.action.as_str().to_string(),
            result,
            detail,
        }
    }
}

/// The outcome of a whole pass — whether a verified plan was applied, per-component results, and
/// whether the trust state advanced. Serializable so the CLI (`--json`, #504-G) can emit it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PassReport {
    /// `false` when the worker returned no verified plan (rejected / transient) — nothing installed.
    pub applied: bool,
    /// When `!applied`, the worker's stable rejection code.
    pub reason: Option<String>,
    /// When `!applied`, the human detail.
    pub detail: Option<String>,
    /// The per-component outcomes.
    pub components: Vec<ComponentOutcome>,
    /// Whether the monotonic trust state advanced (only when every actionable component succeeded).
    pub state_advanced: bool,
}

impl PassReport {
    /// A fail-closed no-op pass: the worker verified nothing installable.
    fn nothing_to_do(reason: &str, detail: &str) -> Self {
        Self {
            applied: false,
            reason: Some(reason.to_string()),
            detail: Some(detail.to_string()),
            components: Vec::new(),
            state_advanced: false,
        }
    }

    /// A prior pass is still holding the single-instance lock (SPEC §8.2) — this invocation exits
    /// immediately without touching anything. An ordinary, expected outcome, not a failure.
    #[must_use]
    pub fn already_running() -> Self {
        Self::nothing_to_do(
            "already_running",
            "a prior pass still holds the single-instance lock; exited without acting",
        )
    }

    /// Auto-updates are currently paused ([`crate::config::UpdaterConfig::is_paused_at`]) — this
    /// invocation exits immediately without touching the network or installing anything. An
    /// ordinary, expected outcome (SPEC §13.1), exactly like [`Self::already_running`]: the
    /// caller — the daily schedule OR a manual `check --now`/`run` — gets a distinct, honest
    /// report rather than a silent no-op or an error.
    #[must_use]
    pub fn paused(paused_until: Option<u64>) -> Self {
        let detail = match paused_until {
            Some(until) => {
                format!("auto-updates are paused until unix time {until}; exited without acting")
            }
            None => "auto-updates are paused; exited without acting".to_string(),
        };
        Self::nothing_to_do("paused", &detail)
    }
}

/// The privileged applier: everything one pass needs to turn a verified plan into installs. The
/// version probes are injectable so the health/enumeration branches are exercised deterministically
/// in tests; production uses [`dig_release_resolver::detect_installed_version`].
pub struct Installer<'a> {
    /// Where the monotonic trust state is persisted.
    pub store: &'a TrustStateStore,
    /// This host's install catalog (component → destination + method).
    pub catalog: &'a Catalog,
    /// The platform whose artifacts are installed.
    pub platform: &'a Platform,
    /// The last-known-good rollback cache.
    pub lkg: &'a LkgCache,
    /// The broker-owned staging directory. Every worker-reported staged path MUST resolve strictly
    /// inside it before the broker reads it (SPEC §8.3 — the worker is untrusted).
    pub staging_dir: &'a Path,
    /// The broker-owned directory a native-package artifact is copied into before its OS installer
    /// runs, so the installer never reads the worker-writable staging path.
    pub apply_dir: &'a Path,
    /// The raw-binary replace retry policy.
    pub retry: RetryPolicy,
    /// The pass clock (unix seconds).
    pub now: u64,
    /// Probe for the ENUMERATION step (what version is installed).
    pub detect: &'a VersionProbe<'a>,
    /// Probe for the HEALTH step (what version is installed AFTER install).
    pub health: &'a VersionProbe<'a>,
    /// Stop/start a service-backed component's OS service around its replace (#666 Bug B).
    /// Production wires [`crate::service::control`]; tests inject a recording fake so the
    /// stop→replace→restart ordering + failure handling are exercised without a real service.
    pub service_ctl: &'a ServiceControl<'a>,
    /// Suppress advancing (and thus persisting) the tracked channel's trust state after an otherwise
    /// fully-successful pass (#621 item 1). Set only when the feed ladder was overridden out-of-band
    /// (`--feed-base`/`$DIG_UPDATER_FEED_BASE`): the fetched manifest's marks may be on a DIFFERENT
    /// channel's version scale, so folding them into `config.channel`'s monotonic state would corrupt
    /// its anti-rollback floor (a below-floor self-DoS). The binaries are still installed; only the
    /// persisted state advance is withheld. A normal (non-overridden) pass leaves this `false`.
    pub suppress_state_advance: bool,
}

impl Installer<'_> {
    /// Apply `report` under the pinned `root` key and persisted `loaded` state (see the module doc
    /// for the ordering).
    ///
    /// # Errors
    ///
    /// - [`BrokerError::ReverifyFailed`] — the worker's plan failed the broker's independent
    ///   re-verification (compromised/buggy worker).
    /// - [`BrokerError::StagingReverifyFailed`] — staged bytes no longer match the signed digest.
    /// - [`BrokerError::StagedArtifactMissing`] — the plan is structurally incomplete.
    /// - [`BrokerError::RollbackFailed`] — a rollback could not complete (integrity concern).
    /// - [`BrokerError::Io`] — a filesystem error persisting state.
    pub fn apply(
        &self,
        root: &VerifyingKey,
        report: &WorkerReport,
        loaded: LoadedState,
    ) -> Result<PassReport, BrokerError> {
        let plan_report = match report {
            WorkerReport::Rejected { reason, detail } => {
                return Ok(PassReport::nothing_to_do(reason, detail));
            }
            WorkerReport::Verified(plan) => plan,
        };

        // 1. Independent re-verify under our OWN pinned key + persisted state (SPEC §8.3).
        let signed = self.reverify_chain(root, &loaded.state, plan_report)?;
        let manifest = &signed.manifest;

        // 2. Enumerate + plan against the RE-VERIFIED manifest.
        let plan = Plan::build(
            manifest,
            &plan_report.artifacts,
            self.catalog,
            self.platform,
            self.detect,
        )?;

        // 3. Apply every OTHER actionable component behind the health gate. The beacon's own
        // component is set aside (`self_component`) rather than applied here — see step 5.
        let mut components = Vec::with_capacity(plan.components.len());
        let mut all_succeeded = true;
        let mut self_component = None;
        for pc in &plan.components {
            if pc.action == UpdateAction::Skip {
                components.push(ComponentOutcome::from(
                    pc,
                    ComponentResult::Skipped,
                    pc.summary.clone(),
                ));
                continue;
            }
            if pc.name == BEACON_COMPONENT_NAME {
                self_component = Some(pc);
                continue;
            }
            let outcome = self.apply_one(pc, manifest.rollback_floor_build)?;
            if outcome.result != ComponentResult::Installed {
                all_succeeded = false;
            }
            components.push(outcome);
        }

        // 4. Advance the trust state ONLY once every OTHER component fully succeeded (SPEC §9
        // step 7) AND the feed was not overridden (`suppress_state_advance` — #621 item 1, so an
        // off-channel `--feed-base` pass never pollutes the tracked channel's monotonic floor).
        // Deliberately independent of the self-update outcome below: the trust state
        // tracks MANIFEST freshness, not which binary the beacon itself currently is, so a merely
        // Deferred self-swap (a common, benign outcome — see `crate::selfupdate`) must never mask
        // an otherwise fully successful pass for everything else.
        let state_advanced = if all_succeeded && !self.suppress_state_advance {
            self.advance_state(manifest, &loaded)?;
            true
        } else {
            false
        };

        // 5. Self-update LAST, after the rest of the pass has fully settled (SPEC §8.1).
        if let Some(pc) = self_component {
            components.push(self.apply_one_self(pc, manifest.rollback_floor_build)?);
        }

        Ok(PassReport {
            applied: true,
            reason: None,
            detail: None,
            components,
            state_advanced,
        })
    }

    /// Re-parse the raw signed feed the worker returned and re-run the whole trust chain under the
    /// pinned `root` and persisted `state`. Any failure is a [`BrokerError::ReverifyFailed`].
    fn reverify_chain(
        &self,
        root: &VerifyingKey,
        state: &TrustState,
        plan_report: &VerifiedPlan,
    ) -> Result<SignedManifest, BrokerError> {
        let delegation =
            SignedDelegation::from_json(&plan_report.delegation_json).map_err(reverify_err)?;
        let manifest =
            SignedManifest::from_json(&plan_report.manifest_json).map_err(reverify_err)?;
        verify_update_chain(root, state, &delegation, &manifest, self.now).map_err(reverify_err)?;
        Ok(manifest)
    }

    /// Apply one ordinary (non-self) actionable component via the generic, per-OS installer
    /// ([`install::install_from_private`](crate::install::install_from_private)).
    fn apply_one(
        &self,
        pc: &PlannedComponent,
        floor: u64,
    ) -> Result<ComponentOutcome, BrokerError> {
        self.apply_component(pc, floor, |private, policy| {
            install_from_private(pc, private, policy)
        })
    }

    /// Apply the beacon's OWN component via [`crate::selfupdate::apply_self_update`] — the
    /// platform-specific self-swap — in place of the generic installer. Called ONLY from
    /// [`Self::apply`], and only after every other component has already settled (see the module
    /// doc's step 5).
    fn apply_one_self(
        &self,
        pc: &PlannedComponent,
        floor: u64,
    ) -> Result<ComponentOutcome, BrokerError> {
        self.apply_component(pc, floor, |private, policy| {
            apply_self_update(private, &pc.dest, policy)
        })
    }

    /// The shared per-component skeleton every actionable component — the beacon's own included —
    /// goes through: contain the staged path → copy-and-verify into a broker-private file →
    /// snapshot → run `install_step` from that private copy → health → rollback. Only the
    /// `install_step` itself differs between an ordinary component and the beacon's self-update.
    ///
    /// The containment + private-copy steps make the hashed-is-installed invariant structural: the
    /// worker-reported path is refused unless it resolves inside the broker-owned staging dir, and
    /// the bytes that are hashed are the exact bytes copied into a file the worker cannot touch and
    /// then installed — closing the reverify→install TOCTOU (SPEC §8.3).
    fn apply_component(
        &self,
        pc: &PlannedComponent,
        floor: u64,
        install_step: impl Fn(&std::path::Path, &RetryPolicy) -> InstallOutcome,
    ) -> Result<ComponentOutcome, BrokerError> {
        // Refuse a staged path that escapes the broker-owned staging dir, BEFORE reading a byte.
        let staged = contained_staged_path(&pc.staged_path, self.staging_dir, &pc.name)?;

        // Copy the staged bytes into a broker-private file and verify THAT copy against the
        // re-verified digest — a mismatch is a security event that aborts the whole pass (SPEC
        // §8.3). From here the install reads only the private copy, so a later staging swap is inert.
        let private = private_target(pc, self.apply_dir);
        let executable = pc.method == InstallMethod::RawBinary;
        stage_and_verify_private(&staged, &private, &pc.expected_digest, &pc.name, executable)?;

        // Snapshot the WHOLE binary set (primary + every alias) so a failed health gate reverts the
        // ENTIRE set together (#666 F2). `install_from_private` refreshes the aliases to the new
        // bytes too, so snapshotting only the primary would let a rollback leave primary-OLD /
        // alias-NEW — the exact #666 split-state. Snapshots are read-only, so taking them BEFORE the
        // service stop is safe and keeps the stop→replace window as short as possible.
        let snapshots = self.snapshot_set(pc)?;

        // #666 Bug B: a service-backed component holds its binary open while it runs, so STOP the
        // service first (releasing the lock) — else the replace defers/fails and the post-install
        // probe reads the still-running old binary. The service id is looked up from the catalog by
        // component name (the applier authority for WHERE/HOW), not carried on the plan.
        let service = self
            .catalog
            .target(&pc.name)
            .and_then(|t| t.service_id())
            .map(str::to_string);
        if let Some(service) = &service {
            if let Err(detail) = (self.service_ctl)(service, ServiceAction::Stop) {
                // The service could not be stopped, so its binary is still locked — do NOT attempt
                // a replace that would defer anyway, and leave the service RUNNING (the stop failed,
                // so nothing was taken down; an already-stopped service is classified as a
                // successful stop by `service::control`, not routed here). Defer to the next pass,
                // cleaning up the private copy.
                let _ = std::fs::remove_file(&private);
                return Ok(ComponentOutcome::from(
                    pc,
                    ComponentResult::Deferred,
                    format!("could not stop service {service} before replace: {detail}"),
                ));
            }
        }

        // Run the install → health → rollback core, then GUARANTEE the service is restarted on EVERY
        // post-stop path — success, deferral, rollback, OR a propagated rollback ERROR (an
        // unreadable/corrupt LKG, a re-verify mismatch, a reinstate-write failure). `restart_after`
        // does NOT `?` the inner result before restarting, so a stopped service is never left down
        // even when the rollback itself errors out (#666 F1).
        let outcome = install_step(&private, &self.retry);
        let install_result = self.finish_apply(pc, floor, snapshots, outcome);
        restart_after(service.as_deref(), self.service_ctl, install_result)
    }

    /// Turn one component's [`InstallOutcome`] into its [`ComponentOutcome`], running the health gate
    /// over the WHOLE binary set (primary + aliases, #666 Bug A) on a successful install and rolling
    /// the whole set back on any failure. Split out from [`Self::apply_component`] so the service
    /// stop/restart can wrap this shared install→health→rollback core.
    fn finish_apply(
        &self,
        pc: &PlannedComponent,
        floor: u64,
        snapshots: Vec<BinarySnapshot>,
        outcome: InstallOutcome,
    ) -> Result<ComponentOutcome, BrokerError> {
        match outcome {
            InstallOutcome::Installed => match self.check_binary_set(pc) {
                // `pc.summary` is the PLAN's pre-install prediction ("v0.14.0 -> v0.15.0") — once
                // the install has actually happened, that prediction is stale. Report what the
                // health gate just re-observed on disk instead (#582), so a later `status` read
                // states verified reality rather than replaying what this pass merely intended.
                Ok(detected) => Ok(ComponentOutcome::from(
                    pc,
                    ComponentResult::Installed,
                    verified_install_detail(&pc.name, &detected),
                )),
                Err(detail) => {
                    self.rollback_set(snapshots, floor)?;
                    Ok(ComponentOutcome::from(
                        pc,
                        ComponentResult::RolledBack,
                        format!("health gate failed, rolled back: {detail}"),
                    ))
                }
            },
            InstallOutcome::Deferred { reason } => Ok(ComponentOutcome::from(
                pc,
                ComponentResult::Deferred,
                reason,
            )),
            InstallOutcome::Failed { detail } => {
                self.rollback_set(snapshots, floor)?;
                Ok(ComponentOutcome::from(
                    pc,
                    ComponentResult::RolledBack,
                    format!("install failed, rolled back: {detail}"),
                ))
            }
        }
    }

    /// Snapshot EVERY binary in a component's set (primary + each byte-identical alias) so a rollback
    /// reverts the whole set together and never leaves a split primary-new/alias-old state (#666 F2).
    /// Each binary is cached under a distinct, filename-safe key (the primary under the component
    /// name — preserving the manual cross-pass rollback contract — each alias under
    /// `{component}--{alias-file-name}`). A binary absent at snapshot time yields a `None` entry (a
    /// fresh placement to be removed, not restored, on rollback).
    fn snapshot_set(&self, pc: &PlannedComponent) -> Result<Vec<BinarySnapshot>, BrokerError> {
        let mut snapshots = Vec::with_capacity(1 + pc.aliases.len());
        snapshots.push(BinarySnapshot {
            dest: pc.dest.clone(),
            entry: self.lkg.snapshot(&pc.name, &pc.dest, pc.installed_build)?,
        });
        for alias in &pc.aliases {
            let key = alias_cache_key(&pc.name, alias);
            snapshots.push(BinarySnapshot {
                dest: alias.clone(),
                entry: self.lkg.snapshot(&key, alias, pc.installed_build)?,
            });
        }
        Ok(snapshots)
    }

    /// Roll back the WHOLE binary set to its pre-pass state (#666 F2): restore each snapshotted
    /// binary in place (floor-exempt — the just-captured current bytes), or remove a binary that was
    /// freshly placed with no prior version. All-or-nothing so no failure path leaves a split set.
    fn rollback_set(&self, snapshots: Vec<BinarySnapshot>, floor: u64) -> Result<(), BrokerError> {
        for snapshot in snapshots {
            match snapshot.entry {
                // The IN-PASS restore of the bytes captured at this destination moments ago — a
                // restore-in-place, floor-EXEMPT so it never leaves the target missing even for an
                // un-ageable prior build (#558).
                Some(entry) => self.lkg.restore(&entry, floor, RestoreKind::InPlace)?,
                None => {
                    if snapshot.dest.exists() {
                        std::fs::remove_file(&snapshot.dest).map_err(|e| {
                            BrokerError::RollbackFailed {
                                component: snapshot.dest.display().to_string(),
                                detail: format!("could not remove freshly-installed binary: {e}"),
                            }
                        })?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Health-gate EVERY binary in a component's set — the primary AND each byte-identical alias
    /// (#666 Bug A) — each must now report the manifest's version. A stale/missing alias fails the
    /// gate exactly like a stale primary, so a component whose alias was left un-refreshed is
    /// rolled back rather than falsely reported Installed. Returns the PRIMARY's observed version
    /// (what a later `status` read states, #582).
    fn check_binary_set(&self, pc: &PlannedComponent) -> Result<DetectedVersion, String> {
        let primary = check_health(&pc.dest, &pc.version, self.health)?;
        for alias in &pc.aliases {
            check_health(alias, &pc.version, self.health).map_err(|detail| {
                format!(
                    "alias {} failed the version check: {detail}",
                    alias.display()
                )
            })?;
        }
        Ok(primary)
    }

    /// Fold the accepted manifest's marks into the trust state and persist it — hardening the state
    /// directory BEFORE this first save (SPEC §6, §9.3; the #504-E harden-before-save finding).
    fn advance_state(&self, manifest: &Manifest, loaded: &LoadedState) -> Result<(), BrokerError> {
        if let Some(state_dir) = self.store.path().parent() {
            std::fs::create_dir_all(state_dir).map_err(|e| BrokerError::Io(e.to_string()))?;
            harden_state_dir(state_dir)?;
        }
        let mut advanced = loaded.state;
        advanced.advance(manifest);
        self.store.save(&advanced, loaded)
    }
}

/// One binary in a component's set paired with its pre-pass snapshot — the unit
/// [`Installer::rollback_set`] reverts. `entry` is `None` when the binary was absent at snapshot
/// time (a fresh placement to REMOVE on rollback, not restore).
struct BinarySnapshot {
    /// The install destination this binary lives at.
    dest: std::path::PathBuf,
    /// Its last-known-good snapshot, or `None` if it did not exist before this pass.
    entry: Option<LkgEntry>,
}

/// The filename-safe LKG cache key for a component's ALIAS binary — distinct from the primary's key
/// (the bare component name) so snapshotting the whole set never collides. Uses the alias file name
/// (never a path with separators or a Windows-illegal `:`), so `dig-node` + `…/dign` →
/// `dig-node--dign`.
fn alias_cache_key(component: &str, alias: &Path) -> String {
    let leaf = alias
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{component}--{leaf}")
}

/// Restart a stopped service AFTER the install→health→rollback core has run, on EVERY path — a
/// success, a deferral, a rollback, OR a propagated rollback ERROR — so a service that was stopped
/// for its replace is NEVER left down (#666 F1). The inner `result` is deliberately NOT `?`-ed
/// before the restart: a rollback that itself errors (unreadable/corrupt LKG, re-verify mismatch,
/// reinstate-write failure) still restarts the service, then the error propagates. A restart failure
/// is folded into the outcome detail as a warning but never turns an otherwise-correct on-disk state
/// into a hard failure (the daily wake + the service manager's own boot recovery bring it back).
fn restart_after(
    service: Option<&str>,
    service_ctl: &ServiceControl,
    result: Result<ComponentOutcome, BrokerError>,
) -> Result<ComponentOutcome, BrokerError> {
    let restart_warning = match service {
        Some(service) => service_ctl(service, ServiceAction::Start)
            .err()
            .map(|detail| format!(" (warning: could not restart {service}: {detail})")),
        None => None,
    };
    // Propagate the install/rollback error ONLY after the restart above has already run.
    let mut outcome = result?;
    if let Some(warning) = restart_warning {
        outcome.detail.push_str(&warning);
    }
    Ok(outcome)
}

/// The production enumeration/health probe: spawn `<path> --version`.
pub fn spawn_version_probe() -> impl Fn(&Path) -> DetectedVersion {
    dig_release_resolver::detect_installed_version
}

/// The detail persisted for a just-installed, health-verified component: what the health gate
/// ACTUALLY found running at its destination (#582), not the plan's pre-install prediction.
/// `detected` is always [`DetectedVersion::Present`] here — [`check_health`]'s success arm only
/// returns after ruling out [`DetectedVersion::Absent`] — but the match stays total rather than
/// unwrapping, so a future change to that invariant fails safe instead of panicking.
fn verified_install_detail(component: &str, detected: &DetectedVersion) -> String {
    match detected {
        DetectedVersion::Present(raw) => format!("{component} now reports {raw}"),
        DetectedVersion::Absent => format!("{component} installed, but its version is unknown"),
    }
}

/// Map a trust rejection during the broker's independent re-verify to a distinct broker error.
fn reverify_err(e: TrustError) -> BrokerError {
    BrokerError::ReverifyFailed(format!("{e} ({})", e.code()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// #666 F1 (the BLOCKER): a stopped service MUST be restarted even when the inner
    /// install/rollback result is an ERROR (a corrupt/unreadable LKG, a re-verify mismatch, a
    /// reinstate-write failure). `restart_after` restarts BEFORE propagating, so the node is never
    /// left down — the property the earlier `?`-first ordering silently violated.
    #[test]
    fn restart_fires_even_when_the_rollback_itself_errors_666f1() {
        let calls = RefCell::new(Vec::new());
        let ctl = |_: &str, action: ServiceAction| {
            calls.borrow_mut().push(action);
            Ok(())
        };
        let rollback_error = Err(BrokerError::RollbackFailed {
            component: "dig-node".into(),
            detail: "cached bytes unreadable".into(),
        });
        let out = restart_after(Some("net.dignetwork.dig-node"), &ctl, rollback_error);
        assert!(
            out.is_err(),
            "the rollback error still propagates to the caller"
        );
        assert_eq!(
            *calls.borrow(),
            vec![ServiceAction::Start],
            "the service was restarted before the error propagated — never left down"
        );
    }

    #[test]
    fn restart_after_folds_a_restart_failure_into_the_detail_without_failing_the_pass() {
        let ctl = |_: &str, _: ServiceAction| Err("boot failed".to_string());
        let ok = Ok(ComponentOutcome {
            component: "dig-node".into(),
            action: "update".into(),
            result: ComponentResult::Installed,
            detail: "dig-node now reports 0.33.0".into(),
        });
        let out = restart_after(Some("net.dignetwork.dig-node"), &ctl, ok).unwrap();
        assert_eq!(
            out.result,
            ComponentResult::Installed,
            "a restart failure never downgrades a good install"
        );
        assert!(
            out.detail.contains("warning: could not restart"),
            "the warning is surfaced: {}",
            out.detail
        );
    }

    #[test]
    fn restart_after_is_a_no_op_for_a_non_service_component() {
        let ctl =
            |_: &str, _: ServiceAction| panic!("must not be called for a service-less component");
        let ok = Ok(ComponentOutcome {
            component: "digstore".into(),
            action: "update".into(),
            result: ComponentResult::Installed,
            detail: "ok".into(),
        });
        assert!(restart_after(None, &ctl, ok).is_ok());
    }

    #[test]
    fn alias_cache_key_is_filename_safe_and_distinct_from_the_primary() {
        let key = alias_cache_key("dig-node", Path::new("/opt/dig/bin/dign"));
        assert_eq!(key, "dig-node--dign");
        assert!(!key.contains('/') && !key.contains('\\') && !key.contains(':'));
    }

    #[test]
    fn component_result_as_str_matches_its_serde_snake_case_rename() {
        for (result, token) in [
            (ComponentResult::Installed, "installed"),
            (ComponentResult::Skipped, "skipped"),
            (ComponentResult::Deferred, "deferred"),
            (ComponentResult::RolledBack, "rolled_back"),
        ] {
            assert_eq!(result.as_str(), token);
            let serialized = serde_json::to_string(&result).unwrap();
            assert_eq!(serialized, format!("\"{token}\""));
        }
    }

    #[test]
    fn verified_install_detail_states_what_was_observed_not_a_plan_prediction() {
        // #582: the persisted detail must name the version the health gate ACTUALLY re-observed
        // on disk, in the caller's own words ("now reports") — never a "vX -> vY" plan summary
        // computed before the install ran.
        let detail = verified_install_detail(
            "dig-dns",
            &DetectedVersion::Present("dig-dns 0.13.0".to_string()),
        );
        assert_eq!(detail, "dig-dns now reports dig-dns 0.13.0");
        assert!(
            !detail.contains("->"),
            "must not read like a plan-time transition summary: {detail}"
        );
    }

    #[test]
    fn paused_is_a_benign_nothing_applied_carrying_the_snooze_deadline() {
        let report = PassReport::paused(Some(1_700_000_000));
        assert!(!report.applied);
        assert_eq!(report.reason.as_deref(), Some("paused"));
        assert!(report.detail.unwrap().contains("1700000000"));
    }

    #[test]
    fn paused_indefinitely_omits_a_deadline_from_the_detail() {
        let report = PassReport::paused(None);
        assert_eq!(report.reason.as_deref(), Some("paused"));
        assert!(!report.detail.unwrap().contains("unix time"));
    }
}
