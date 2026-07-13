//! The persistent, monotonic trust state — the beacon's memory of the freshest feed it has
//! ever accepted. It is what turns a validly-signed *old* manifest (a freeze/rollback
//! replay) into a rejected one.
//!
//! The beacon persists this alongside its config in an Admin/SYSTEM-only location and loads
//! it before each pass. [`verify_freshness`](crate::verify::verify_freshness) checks a
//! candidate manifest against it; [`TrustState::advance`] folds an accepted manifest's
//! high-water-marks back in. The marks only ever move forward.

use serde::{Deserialize, Serialize};

use crate::manifest::Manifest;

/// The freshest values the beacon has ever accepted. Compared against each candidate
/// manifest to enforce anti-rollback (`sequence`), anti-freeze (`generated`), delegation
/// monotonicity (`root_version`), and the anti-downgrade floor (`rollback_floor_build`).
///
/// `Serialize`/`Deserialize` cover the broker↔worker request wire (the four monotonic marks the
/// unprivileged worker needs for its freshness checks). On-disk persistence — which additionally
/// PRESERVES unknown fields for forward-compatibility — is the privileged broker's concern
/// (`dig_updater_broker::state`), not this pure type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrustState {
    /// Highest delegation `root_version` ever accepted.
    pub root_version: u32,
    /// Highest manifest `sequence` ever accepted.
    pub sequence: u64,
    /// Highest manifest `generated` timestamp ever accepted.
    pub generated: u64,
    /// Highest `rollback_floor_build` ever accepted. The floor never lowers, so a later
    /// manifest can raise the downgrade floor but never quietly drop it.
    pub rollback_floor_build: u64,
}

impl TrustState {
    /// The initial state for a fresh install: zeroed, so the first validly-signed,
    /// unexpired manifest is accepted and establishes the baseline.
    #[must_use]
    pub fn initial() -> Self {
        Self::default()
    }

    /// Fold an accepted manifest's high-water-marks into the state. Each mark moves to the
    /// max of its current and the manifest's value, so the state is monotonic even if
    /// `advance` is ever called with an older manifest.
    pub fn advance(&mut self, manifest: &Manifest) {
        self.root_version = self.root_version.max(manifest.root_version);
        self.sequence = self.sequence.max(manifest.sequence);
        self.generated = self.generated.max(manifest.generated);
        self.rollback_floor_build = self.rollback_floor_build.max(manifest.rollback_floor_build);
    }
}
