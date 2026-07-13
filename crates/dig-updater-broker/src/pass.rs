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
use crate::rollback::{LkgCache, LkgEntry};
use crate::secure::harden_state_dir;
use crate::selfupdate::apply_self_update;
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

/// The per-component result line of a [`PassReport`] — agent-consumable (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentOutcome {
    /// The component name.
    pub component: String,
    /// The planned action (`install` / `update` / `skip`).
    pub action: String,
    /// What actually happened.
    pub result: ComponentResult,
    /// A human-readable detail (the version transition, or the failure reason).
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
        // step 7). Deliberately independent of the self-update outcome below: the trust state
        // tracks MANIFEST freshness, not which binary the beacon itself currently is, so a merely
        // Deferred self-swap (a common, benign outcome — see `crate::selfupdate`) must never mask
        // an otherwise fully successful pass for everything else.
        let state_advanced = if all_succeeded {
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

        // Snapshot the currently-installed binary so a failed health gate can revert to it.
        let snapshot = self.lkg.snapshot(&pc.name, &pc.dest, pc.installed_build)?;

        match install_step(&private, &self.retry) {
            InstallOutcome::Installed => match check_health(&pc.dest, &pc.version, self.health) {
                Ok(()) => Ok(ComponentOutcome::from(
                    pc,
                    ComponentResult::Installed,
                    pc.summary.clone(),
                )),
                Err(detail) => {
                    self.rollback(snapshot, &pc.dest, floor)?;
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
                self.rollback(snapshot, &pc.dest, floor)?;
                Ok(ComponentOutcome::from(
                    pc,
                    ComponentResult::RolledBack,
                    format!("install failed, rolled back: {detail}"),
                ))
            }
        }
    }

    /// Revert a component: restore its last-known-good snapshot (re-verified, floor-bounded), or —
    /// for a fresh install that had no prior build — remove what was just placed.
    fn rollback(
        &self,
        snapshot: Option<LkgEntry>,
        dest: &Path,
        floor: u64,
    ) -> Result<(), BrokerError> {
        match snapshot {
            Some(entry) => self.lkg.restore(&entry, floor),
            None => {
                if dest.exists() {
                    std::fs::remove_file(dest).map_err(|e| BrokerError::RollbackFailed {
                        component: dest.display().to_string(),
                        detail: format!("could not remove freshly-installed binary: {e}"),
                    })?;
                }
                Ok(())
            }
        }
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

/// The production enumeration/health probe: spawn `<path> --version`.
pub fn spawn_version_probe() -> impl Fn(&Path) -> DetectedVersion {
    dig_release_resolver::detect_installed_version
}

/// Map a trust rejection during the broker's independent re-verify to a distinct broker error.
fn reverify_err(e: TrustError) -> BrokerError {
    BrokerError::ReverifyFailed(format!("{e} ({})", e.code()))
}
