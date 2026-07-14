//! The beacon's UNPRIVILEGED status snapshot (SPEC §13.2): `status.json`, written by the broker
//! after every `check`/`run`/config-change, and readable by ANYONE — no elevation, unlike
//! [`crate::config`] / [`crate::state`]. This is what `dig-updater status`, the dig-node updater
//! RPC proxy (#515), and the Updates UI (#516) read to answer "is the beacon current/paused"
//! without needing to be Administrator/root.
//!
//! Deliberately NOT authoritative: the ENFORCEMENT copy of the trust marks lives in the
//! Admin-only `trust-state.json` ([`crate::state::TrustStateStore`]); this file only MIRRORS them
//! for observability. An unprivileged reader that trusted this file for a SECURITY decision would
//! be trusting an unauthenticated local file — fine for "should I show a badge", never for
//! "should I install this". Because of that, a failure to read it degrades to
//! [`StatusSnapshot::never_checked`] rather than an error (SPEC §13.2: status is ALWAYS
//! answerable) — unlike the trust state, which fails closed on corruption.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use dig_updater_trust::TrustState;

use crate::config::{Channel, UpdaterConfig};
use crate::error::BrokerError;
use crate::persist::write_json_atomic;
use crate::secure::harden_public_status_path;
use crate::PassReport;
use dig_updater_worker::WorkerReport;

/// The current on-disk schema of [`StatusSnapshot`] (SPEC §13.2).
pub const STATUS_SCHEMA: u32 = 1;

const STATUS_FILE: &str = "status.json";

/// One component's most-recently-observed decision: either a dry check's staged-artifact preview
/// (`action: "would_fetch"`) or a full pass's install/skip/defer/rollback outcome. A dry check
/// never enumerates installed versions (only a full pass does, via
/// [`crate::pass::Installer`]), so it cannot report a plan DECISION — only what it verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// The component name (e.g. `dig-node`).
    pub component: String,
    /// What was planned or observed (`would_fetch`, or the pass's `install`/`update`/`skip`).
    pub action: String,
    /// What actually happened (`staged`, or the pass's `installed`/`skipped`/`deferred`/`rolled_back`).
    pub result: String,
    /// A human-readable detail (the version transition, or the failure reason).
    pub detail: String,
}

/// Everything the broker knows when it is about to persist a [`StatusSnapshot`]: the current
/// config, the pass clock, a best-effort next-wake estimate, and the trust marks to mirror.
/// Threading these through one context avoids a five-plus-argument builder signature.
pub struct StatusContext<'a> {
    /// The persisted channel/pause configuration in effect for this snapshot.
    pub config: &'a UpdaterConfig,
    /// The pass clock (unix seconds) — the SAME clock the pass itself used.
    pub now: u64,
    /// A best-effort estimate of when the daily schedule will next wake the beacon, if it is
    /// registered (SPEC §8.4) — `None` when no schedule is registered. An ESTIMATE (the daily
    /// cadence from `now`), not a parse of the OS scheduler's own next-run time.
    pub next_wake: Option<u64>,
    /// The persisted trust state to mirror (informational only — see the module doc).
    pub trust_state: TrustState,
}

/// The beacon's unprivileged, world-readable status (SPEC §13.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusSnapshot {
    /// The on-disk schema version ([`STATUS_SCHEMA`]).
    #[serde(default = "current_status_schema")]
    pub schema: u32,
    /// The beacon binary version that wrote this snapshot.
    pub version: String,
    /// The update channel currently configured.
    pub channel: Channel,
    /// Whether auto-updates are paused RIGHT NOW (the effective value — a lapsed timed pause
    /// reports `false` here even before an explicit `resume`, SPEC §13.1).
    pub paused: bool,
    /// The configured pause expiry, if any (mirrors [`UpdaterConfig::paused_until`]).
    pub paused_until: Option<u64>,
    /// When the beacon last checked/ran, as unix seconds — `None` if it never has.
    pub last_check: Option<u64>,
    /// Whether the last check was a dry verify (`"dry"`) or a full pass (`"run"`).
    pub last_check_kind: Option<String>,
    /// The broad outcome category of the last check/run: `"verified"` | `"rejected"` |
    /// `"applied"` | `"nothing_applied"`.
    pub last_outcome: Option<String>,
    /// The specific machine-classifiable reason when the outcome was not a plain success (a
    /// worker rejection code, or a pass's `already_running`/`paused`/etc.) — `None` on success.
    pub last_reason: Option<String>,
    /// A human-readable detail for the last outcome.
    pub last_detail: Option<String>,
    /// The last-observed per-component decisions.
    pub components: Vec<ComponentStatus>,
    /// A best-effort estimate of the next scheduled wake, if the daily schedule is registered.
    pub next_wake: Option<u64>,
    /// A mirror of the persisted trust marks — informational only (see the module doc).
    pub trust_state: TrustState,
}

fn current_status_schema() -> u32 {
    STATUS_SCHEMA
}

impl StatusSnapshot {
    /// The default snapshot when NOTHING has ever been recorded (a fresh install, or a reader
    /// that lacks access to a status file this beacon actually wrote) — never an error.
    #[must_use]
    pub fn never_checked() -> Self {
        Self {
            schema: STATUS_SCHEMA,
            version: env!("CARGO_PKG_VERSION").to_string(),
            channel: Channel::default(),
            paused: false,
            paused_until: None,
            last_check: None,
            last_check_kind: None,
            last_outcome: None,
            last_reason: None,
            last_detail: None,
            components: Vec::new(),
            next_wake: None,
            trust_state: TrustState::initial(),
        }
    }

    /// Build the snapshot to persist after a DRY check ([`crate::Broker::dry_check`]): the
    /// staged-artifact preview when verified, or the rejection reason when not. Never a plan
    /// decision — see the type doc.
    #[must_use]
    pub fn from_dry_check(report: &WorkerReport, ctx: &StatusContext<'_>) -> Self {
        let (outcome, reason, detail, components) = match report {
            WorkerReport::Verified(plan) => (
                "verified",
                None,
                format!(
                    "{} artifact(s) staged from {}",
                    plan.artifacts.len(),
                    plan.source
                ),
                plan.artifacts
                    .iter()
                    .map(|a| ComponentStatus {
                        component: a.component.clone(),
                        action: "would_fetch".to_string(),
                        result: "staged".to_string(),
                        detail: format!("{} [{}-{}]", a.version, a.os, a.arch),
                    })
                    .collect(),
            ),
            WorkerReport::Rejected { reason, detail } => {
                ("rejected", Some(reason.clone()), detail.clone(), Vec::new())
            }
        };
        Self::base(ctx, "dry", outcome, reason, Some(detail), components)
    }

    /// Build the snapshot to persist after a FULL pass ([`crate::Broker::run_once_with_feed`]):
    /// the per-component install/skip/defer/rollback decisions.
    #[must_use]
    pub fn from_pass(report: &PassReport, ctx: &StatusContext<'_>) -> Self {
        let outcome = if report.applied {
            "applied"
        } else {
            "nothing_applied"
        };
        let components = report
            .components
            .iter()
            .map(|c| ComponentStatus {
                component: c.component.clone(),
                action: c.action.clone(),
                result: c.result.as_str().to_string(),
                detail: c.detail.clone(),
            })
            .collect();
        Self::base(
            ctx,
            "run",
            outcome,
            report.reason.clone(),
            report.detail.clone(),
            components,
        )
    }

    /// The fields every builder shares: the mirrored config/trust-state + the caller-supplied
    /// outcome/reason/detail/components.
    fn base(
        ctx: &StatusContext<'_>,
        kind: &str,
        outcome: &str,
        reason: Option<String>,
        detail: Option<String>,
        components: Vec<ComponentStatus>,
    ) -> Self {
        Self {
            schema: STATUS_SCHEMA,
            version: env!("CARGO_PKG_VERSION").to_string(),
            channel: ctx.config.channel,
            paused: ctx.config.is_paused_at(ctx.now),
            paused_until: ctx.config.paused_until,
            last_check: Some(ctx.now),
            last_check_kind: Some(kind.to_string()),
            last_outcome: Some(outcome.to_string()),
            last_reason: reason,
            last_detail: detail,
            components,
            next_wake: ctx.next_wake,
            trust_state: ctx.trust_state,
        }
    }
}

/// Reads and writes the persisted [`StatusSnapshot`] under a WORLD-READABLE status directory —
/// deliberately NOT the Admin-only state directory (see the module doc).
pub struct StatusStore {
    path: PathBuf,
}

impl StatusStore {
    /// A store rooted at `status_dir` (the file is `<status_dir>/status.json`).
    #[must_use]
    pub fn at(status_dir: &Path) -> Self {
        Self {
            path: status_dir.join(STATUS_FILE),
        }
    }

    /// The path of the status file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the last-persisted snapshot. ANY read failure — missing file, or a permission an
    /// unprivileged reader legitimately lacks — degrades to [`StatusSnapshot::never_checked`], NOT
    /// an error: "status" must always be answerable (SPEC §13.2). A file that IS readable but not
    /// valid JSON is genuine corruption and still surfaces as [`BrokerError::StateCorrupt`].
    pub fn load(&self) -> Result<StatusSnapshot, BrokerError> {
        let Ok(bytes) = std::fs::read(&self.path) else {
            return Ok(StatusSnapshot::never_checked());
        };
        serde_json::from_slice(&bytes)
            .map_err(|e| BrokerError::StateCorrupt(format!("status: {e}")))
    }

    /// Persist `snapshot`, then (re-)harden the file and its directory world-readable — the
    /// broker is the only writer, but any identity may read (SPEC §13.2).
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] on any create/harden/write/rename failure.
    pub fn save(&self, snapshot: &StatusSnapshot) -> Result<(), BrokerError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| BrokerError::Io(e.to_string()))?;
            harden_public_status_path(dir)?;
        }
        let bytes =
            serde_json::to_vec_pretty(snapshot).map_err(|e| BrokerError::Io(e.to_string()))?;
        write_json_atomic(&self.path, &bytes)?;
        harden_public_status_path(&self.path)
    }
}

/// The current wall clock as a [`StatusContext`] convenience default — production callers always
/// go through [`crate::Broker`], which supplies the real `next_wake`/`trust_state`; this is only
/// for the doc example / trivial construction in tests.
#[cfg(test)]
impl<'a> StatusContext<'a> {
    fn for_test(config: &'a UpdaterConfig) -> Self {
        Self {
            config,
            now: crate::now_unix_secs(),
            next_wake: None,
            trust_state: TrustState::initial(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_updater_worker::{StagedArtifact, VerifiedPlan};

    fn store() -> (tempfile::TempDir, StatusStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = StatusStore::at(dir.path());
        (dir, store)
    }

    #[test]
    fn missing_file_loads_as_never_checked() {
        let (_dir, store) = store();
        let snapshot = store.load().expect("load");
        assert_eq!(snapshot, StatusSnapshot::never_checked());
    }

    #[test]
    fn save_then_load_round_trips() {
        let (_dir, store) = store();
        let config = UpdaterConfig::default();
        let ctx = StatusContext::for_test(&config);
        let snapshot = StatusSnapshot::from_dry_check(
            &WorkerReport::Rejected {
                reason: "manifest_expired".into(),
                detail: "expired at 1, now 2".into(),
            },
            &ctx,
        );
        store.save(&snapshot).expect("save");
        assert_eq!(store.load().expect("load"), snapshot);
    }

    #[test]
    fn corrupt_status_file_is_a_genuine_error_not_a_silent_reset() {
        let (dir, store) = store();
        std::fs::write(dir.path().join("status.json"), b"{ not json").unwrap();
        let err = store
            .load()
            .expect_err("a readable-but-corrupt file is a real error");
        assert!(matches!(err, BrokerError::StateCorrupt(_)));
    }

    #[test]
    fn an_unreadable_directory_degrades_to_never_checked_not_an_error() {
        // Standing in for an unprivileged reader who cannot even list the status directory:
        // pointing at a status.json that does not exist inside an ordinary missing directory
        // must never error — status is ALWAYS answerable (SPEC §13.2).
        let missing_dir = std::env::temp_dir().join("dig-updater-status-definitely-missing");
        let store = StatusStore::at(&missing_dir);
        assert_eq!(store.load().expect("load"), StatusSnapshot::never_checked());
    }

    fn verified_plan() -> WorkerReport {
        WorkerReport::Verified(VerifiedPlan {
            source: "https://updates.dig.net/v1/alpha".into(),
            schema: 1,
            root_version: 1,
            sequence: 42,
            generated: 1000,
            rollback_floor_build: 20,
            delegation_json: "{}".into(),
            manifest_json: "{}".into(),
            artifacts: vec![StagedArtifact {
                component: "dig-node".into(),
                version: "0.26.0".into(),
                build: 26,
                os: "linux".into(),
                arch: "x64".into(),
                sha256: "ab".into(),
                size: 10,
                staged_path: "/tmp/staging/dig-node".into(),
            }],
        })
    }

    #[test]
    fn from_dry_check_verified_lists_staged_artifacts_as_would_fetch() {
        let config = UpdaterConfig::default();
        let ctx = StatusContext::for_test(&config);
        let snapshot = StatusSnapshot::from_dry_check(&verified_plan(), &ctx);
        assert_eq!(snapshot.last_outcome.as_deref(), Some("verified"));
        assert_eq!(snapshot.last_check_kind.as_deref(), Some("dry"));
        assert_eq!(snapshot.components.len(), 1);
        assert_eq!(snapshot.components[0].component, "dig-node");
        assert_eq!(snapshot.components[0].action, "would_fetch");
    }

    #[test]
    fn from_dry_check_rejected_carries_the_reason_and_no_components() {
        let config = UpdaterConfig::default();
        let ctx = StatusContext::for_test(&config);
        let snapshot = StatusSnapshot::from_dry_check(
            &WorkerReport::Rejected {
                reason: "digest_mismatch".into(),
                detail: "sha256 did not match".into(),
            },
            &ctx,
        );
        assert_eq!(snapshot.last_outcome.as_deref(), Some("rejected"));
        assert_eq!(snapshot.last_reason.as_deref(), Some("digest_mismatch"));
        assert!(snapshot.components.is_empty());
    }

    #[test]
    fn from_pass_mirrors_paused_effectively_even_if_the_stored_flag_lags() {
        // A lapsed timed pause: `paused` is still literally `true` in config, but its
        // `paused_until` has already passed — the snapshot must report the EFFECTIVE (false)
        // value, not the raw stored flag (SPEC §13.1/§13.2).
        let config = UpdaterConfig {
            paused: true,
            paused_until: Some(50),
            ..UpdaterConfig::default()
        };
        let ctx = StatusContext {
            config: &config,
            now: 100,
            next_wake: None,
            trust_state: TrustState::initial(),
        };
        let snapshot = PassReport::already_running();
        let status = StatusSnapshot::from_pass(&snapshot, &ctx);
        assert!(
            !status.paused,
            "a lapsed snooze must report unpaused, not the stale stored flag"
        );
    }

    #[test]
    fn from_pass_applied_lists_every_component_outcome() {
        use crate::{ComponentOutcome, ComponentResult};
        let config = UpdaterConfig::default();
        let ctx = StatusContext::for_test(&config);
        let report = PassReport {
            applied: true,
            reason: None,
            detail: None,
            components: vec![ComponentOutcome {
                component: "digstore".into(),
                action: "update".into(),
                result: ComponentResult::Installed,
                detail: "v0.1.0 -> v0.2.0".into(),
            }],
            state_advanced: true,
        };
        let snapshot = StatusSnapshot::from_pass(&report, &ctx);
        assert_eq!(snapshot.last_outcome.as_deref(), Some("applied"));
        assert_eq!(snapshot.components[0].result, "installed");
    }
}
