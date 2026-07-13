//! The broker↔worker IPC contract: the [`WorkerRequest`] the privileged broker pipes in, and
//! the [`WorkerReport`] the worker prints back. Both are stable JSON so the boundary is
//! auditable and agent-consumable (§6.2).

use serde::{Deserialize, Serialize};

use dig_updater_trust::TrustState;

use crate::error::WorkerError;
use crate::feed::{FeedSource, Platform};

/// What the broker asks the worker to verify. It deliberately carries NO root key — the worker
/// binary pins the one trusted root key itself, so nothing on this channel can redirect trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRequest {
    /// The feed sources to try, in order (untrusted transport).
    pub feed_sources: Vec<FeedSource>,
    /// The persisted monotonic trust state to enforce freshness against.
    pub trust_state: TrustState,
    /// The current time, as unix seconds. Supplied by the broker so the pass has one clock.
    pub now: u64,
    /// A directory the (unprivileged) worker may write verified artifacts into.
    pub staging_dir: String,
    /// The platform whose artifacts to download and verify.
    pub platform: Platform,
}

/// One artifact the worker downloaded and digest-verified, staged for the broker to install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedArtifact {
    /// The component this artifact belongs to (e.g. `dig-node`).
    pub component: String,
    /// The component's human-facing version.
    pub version: String,
    /// The component's monotonic build number.
    pub build: u64,
    /// The artifact's OS token.
    pub os: String,
    /// The artifact's arch token.
    pub arch: String,
    /// The verified lowercase-hex SHA-256 (equals the signed manifest's digest).
    pub sha256: String,
    /// The number of bytes written to staging (the actual downloaded size).
    pub size: u64,
    /// The absolute path of the verified file in the staging directory.
    pub staged_path: String,
}

/// The worker's verdict for one pass. `Verified` means the whole trust chain passed and every
/// listed artifact's bytes matched their signed digest; `Rejected` carries a stable `reason`
/// code (from [`WorkerError::code`]) and a human `detail`. Fails closed: anything other than a
/// clean, fully-verified pass is a `Rejected`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WorkerReport {
    /// The feed verified end-to-end; `artifacts` are staged and digest-verified.
    Verified(VerifiedPlan),
    /// The pass was rejected; nothing may be installed.
    Rejected {
        /// A stable machine-classifiable code (`manifest_expired`, `digest_mismatch`, …).
        reason: String,
        /// A human-readable explanation.
        detail: String,
    },
}

impl WorkerReport {
    /// Build a `Rejected` report from a worker failure, capturing its stable code + message.
    #[must_use]
    pub fn rejected(err: &WorkerError) -> Self {
        Self::Rejected {
            reason: err.code().to_string(),
            detail: err.to_string(),
        }
    }
}

/// A fully-verified update plan: the accepted manifest's freshness marks, the staged
/// digest-verified artifacts, AND the exact signed feed bytes the worker verified. This is what
/// the worker returns on success and what the privileged broker (in -E) INDEPENDENTLY re-verifies
/// under its own pinned root key before installing — the worker's word is never trusted on the
/// install path (SPEC §8.3).
///
/// The `delegation_json` / `manifest_json` fields carry the exact envelope bytes the worker
/// fetched so the broker re-runs the whole signature chain without touching the network itself:
/// even a fully compromised worker cannot fabricate a plan that survives the broker's re-verify,
/// because it does not hold a key that chains to the pinned root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedPlan {
    /// The feed source base URL that served the accepted feed.
    pub source: String,
    /// The accepted manifest's schema version.
    pub schema: u32,
    /// The accepted delegation/manifest `root_version`.
    pub root_version: u32,
    /// The accepted manifest `sequence`.
    pub sequence: u64,
    /// The accepted manifest `generated` timestamp.
    pub generated: u64,
    /// The accepted manifest `rollback_floor_build`.
    pub rollback_floor_build: u64,
    /// The exact `delegation.json` envelope bytes the worker fetched + verified, so the broker can
    /// re-verify the delegation signature under its OWN pinned root key (SPEC §8.3).
    pub delegation_json: String,
    /// The exact `manifest.json` envelope bytes the worker fetched + verified, so the broker can
    /// re-verify the manifest signature + freshness + floor under its own pinned key.
    pub manifest_json: String,
    /// The staged, digest-verified artifacts for the requested platform.
    pub artifacts: Vec<StagedArtifact>,
}

impl VerifiedPlan {
    /// Wrap this plan in a `Verified` report.
    #[must_use]
    pub fn into_report(self) -> WorkerReport {
        WorkerReport::Verified(self)
    }
}
