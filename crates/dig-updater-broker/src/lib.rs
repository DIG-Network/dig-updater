#![warn(missing_docs)]

//! # dig-updater-broker — the privileged broker
//!
//! The broker is the **privileged** half of the beacon's two-process split (SPEC §8.3). It holds
//! the rights to persist the Admin/SYSTEM-only trust state and (in follow-ups) to replace on-disk
//! binaries, but it does NOT touch the network. Instead it spawns the **unprivileged**
//! [`dig_updater_worker`] to fetch + verify, receives only a verified plan back, and — in the
//! install path (#504-E) — applies installs behind a health gate and rolls back on failure.
//!
//! This crate implements the -D + -E surface: loading the persisted trust state, spawning the
//! worker with dropped privileges ([`sandbox`]), a **dry check** ([`Broker::dry_check`]) that
//! verifies without installing, and the full install path ([`Broker::run_once`]) — enumerate,
//! ACL self-check, independent re-verify under the pinned key, staging re-verify, silent per-OS
//! install, health gate, and re-verified rollback ([`pass::Installer`]). The scheduler /
//! single-instance lock / self-update (#504-F) remain a separate ticket.
//!
//! ## Never trust the worker on the install path (SPEC §8.3)
//!
//! The worker is unprivileged and network-facing, so its report is treated as untrusted input:
//! before installing anything, the broker RE-VERIFIES the whole signature chain under its OWN
//! pinned root key ([`pass::Installer`] step 1) and re-hashes each staged artifact against the
//! re-verified digest immediately before it is applied. The trust state advances ONLY after a
//! component installs AND passes its health gate, and never before the state directory is hardened.
//!
//! ## The one `unsafe` in the workspace
//!
//! Privilege-dropping needs OS primitives, so [`sandbox`] is the single module that uses
//! `unsafe` (Unix `setuid`/`setgid`; Windows restricted-token spawn). Every other module — and
//! every other crate — is safe.

mod error;
mod hashing;
pub mod health;
pub mod install;
mod pass;
pub mod paths;
pub mod plan;
pub mod rollback;
pub mod sandbox;
pub mod secure;
mod spawn;
pub mod state;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dig_updater_trust::beacon_root_verifying_key;
use dig_updater_worker::{
    production_feed_ladder, FeedSource, Platform, WorkerReport, WorkerRequest,
};

// Re-exported so consumers (the CLI, tests) can read the enumeration/health probe's inputs +
// outputs without depending on `dig-release-resolver` directly — the broker owns that contract.
pub use dig_release_resolver::{DetectedVersion, UpdateAction};

pub use error::BrokerError;
pub use health::VersionProbe;
pub use install::RetryPolicy;
pub use pass::{ComponentOutcome, ComponentResult, Installer, PassReport};
pub use plan::{Catalog, ComponentTarget, InstallMethod, Plan, PlannedComponent};
pub use rollback::LkgCache;
pub use sandbox::Sandbox;
pub use secure::Repair;
pub use spawn::spawn_worker;
pub use state::{LoadedState, TrustStateStore};

/// The privileged orchestrator. Constructed once per beacon pass.
#[derive(Debug, Clone)]
pub struct Broker {
    state_dir: PathBuf,
    worker_path: PathBuf,
}

impl Broker {
    /// A broker using the default OS state directory and the sibling worker binary.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] if the worker binary path cannot be resolved.
    pub fn new() -> Result<Self, BrokerError> {
        Ok(Self {
            state_dir: paths::default_state_dir(),
            worker_path: paths::sibling_worker_binary()?,
        })
    }

    /// A broker with explicit paths — used by tests and custom deployments.
    #[must_use]
    pub fn with_paths(state_dir: PathBuf, worker_path: PathBuf) -> Self {
        Self {
            state_dir,
            worker_path,
        }
    }

    /// The state directory this broker reads/writes.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Run a **dry** update check: load the persisted trust state, spawn the unprivileged worker
    /// to fetch + verify the feed and stage the artifacts, and return its report. This performs
    /// NO install and NEVER advances the trust state (SPEC §9 step 7 gates advancement on a
    /// health-checked install, which is #504-E).
    ///
    /// # Errors
    ///
    /// [`BrokerError`] if the state cannot be loaded or the worker cannot be run.
    pub fn dry_check(&self, feed_sources: Vec<FeedSource>) -> Result<WorkerReport, BrokerError> {
        let loaded = TrustStateStore::at(&self.state_dir).load()?;
        let report = self.fetch_and_verify(feed_sources, loaded.state, Sandbox::Restricted)?;
        Ok(report)
    }

    /// Run exactly one FULL update pass: ACL self-check → spawn the unprivileged worker to fetch +
    /// verify + stage → INDEPENDENTLY re-verify under the pinned key → enumerate → silent per-OS
    /// install behind a health gate → re-verified rollback on failure → advance the trust state
    /// only on full success. This is the beacon's production entry point (SPEC §9, §9.5).
    ///
    /// # Errors
    ///
    /// [`BrokerError::AclViolation`] if a guarded path is unsafely writable; [`BrokerError::Spawn`]
    /// if the worker cannot be run; [`BrokerError::ReverifyFailed`] / [`BrokerError::StagingReverifyFailed`]
    /// if the worker's plan fails the broker's independent re-verification; [`BrokerError::RollbackFailed`]
    /// if a rollback cannot complete; [`BrokerError::Io`] on a filesystem error.
    pub fn run_once(&self) -> Result<PassReport, BrokerError> {
        let root = beacon_root_verifying_key();
        let probe = pass::spawn_version_probe();
        self.run_pass(
            &root,
            production_feed_ladder(),
            Sandbox::Restricted,
            &probe,
            &probe,
        )
    }

    /// Manually roll every cached component back to its last-known-good build, re-verifying the
    /// cached bytes against their recorded digest + the current rollback floor before reinstating
    /// (SPEC §9.5). A recovery entry point (a failed pass already rolls back in-line).
    ///
    /// The rollback floor is read from the PERSISTED, Admin/SYSTEM-only trust state — never a
    /// caller-supplied value. The last-known-good record's digest is self-recorded beside the
    /// cached bytes, so a floor the caller could also choose would let a below-floor (vulnerable)
    /// build be reinstated; anchoring the floor to the hardened trust state closes that (SPEC §6,
    /// §9.5).
    ///
    /// # Errors
    ///
    /// [`BrokerError::RollbackFailed`] if a cached build cannot be re-verified or is below the
    /// floor; [`BrokerError::StateCorrupt`] if the persisted state is malformed; [`BrokerError::Io`]
    /// on a filesystem error.
    pub fn rollback(&self) -> Result<Vec<String>, BrokerError> {
        let floor = TrustStateStore::at(&self.state_dir)
            .load()?
            .state
            .rollback_floor_build;
        let cache = LkgCache::at(self.lkg_dir());
        let mut restored = Vec::new();
        for component in cache.cached_components() {
            let entry = cache.load_entry(&component)?;
            cache.restore(&entry, floor)?;
            restored.push(component);
        }
        Ok(restored)
    }

    /// The full production pass, parameterized by the trust `root` and version `probe`s so the
    /// pinned-key entry point ([`run_once`](Self::run_once)) and future callers share one body.
    fn run_pass(
        &self,
        root: &ed25519_dalek::VerifyingKey,
        feed_sources: Vec<FeedSource>,
        sandbox: Sandbox,
        detect: &health::VersionProbe,
        health: &health::VersionProbe,
    ) -> Result<PassReport, BrokerError> {
        let store = TrustStateStore::at(&self.state_dir);
        let staging_dir = self.staging_dir();
        let apply_dir = self.apply_dir();
        let lkg = LkgCache::at(self.lkg_dir());

        // ACL self-check FIRST, fail-closed: the state / last-known-good / apply directories are
        // created AND EXPLICITLY HARDENED, and the beacon binary is verified un-tamperable, BEFORE
        // we fetch or install anything (SPEC §8.3, §9.3). The explicit harden matters on Windows:
        // the ACL self-check's alpha-floor classifier reports every existing path AdminOnly, so it
        // never triggers the repair-harden branch — the state / lkg / apply dirs would otherwise be
        // created but never `icacls`-locked. Snapshots land in the lkg dir BEFORE any state advance,
        // so it must be hardened up front (#504-E).
        for dir in [&self.state_dir, &self.lkg_dir(), &apply_dir] {
            std::fs::create_dir_all(dir).map_err(|e| BrokerError::Io(e.to_string()))?;
            secure::harden_state_dir(dir)?;
        }
        secure::acl_self_check(&self.guarded_paths())?;
        // Staging must be writable by the (possibly privilege-dropped) worker yet non-world-writable.
        sandbox::prepare_worker_writable_dir(&staging_dir, sandbox)?;

        let loaded = store.load()?;
        let report = self.fetch_and_verify(feed_sources, loaded.state, sandbox)?;

        let installer = Installer {
            store: &store,
            catalog: &Catalog::alpha_defaults(&Platform::current()),
            platform: &Platform::current(),
            lkg: &lkg,
            staging_dir: &staging_dir,
            apply_dir: &apply_dir,
            retry: RetryPolicy::default(),
            now: now_unix_secs(),
            detect,
            health,
        };
        installer.apply(root, &report, loaded)
    }

    /// Spawn the unprivileged worker to fetch + verify + stage, returning its report.
    fn fetch_and_verify(
        &self,
        feed_sources: Vec<FeedSource>,
        trust_state: dig_updater_trust::TrustState,
        sandbox: Sandbox,
    ) -> Result<WorkerReport, BrokerError> {
        let request = WorkerRequest {
            feed_sources,
            trust_state,
            now: now_unix_secs(),
            staging_dir: self.staging_dir().to_string_lossy().into_owned(),
            platform: Platform::current(),
        };
        spawn_worker(&self.worker_path, &request, sandbox)
    }

    /// The guarded paths the ACL self-check verifies each pass. Directories the broker owns are
    /// repairable; the beacon binary is not (the broker must never chmod its own image). The
    /// scheduler artifact + single-instance lock join this set in #504-F.
    fn guarded_paths(&self) -> Vec<(PathBuf, Repair)> {
        let mut paths = vec![
            (self.state_dir.clone(), Repair::IfOwned),
            (self.staging_dir(), Repair::IfOwned),
            (self.lkg_dir(), Repair::IfOwned),
            (self.apply_dir(), Repair::IfOwned),
        ];
        if let Ok(exe) = std::env::current_exe() {
            paths.push((exe, Repair::Never));
        }
        paths
    }

    /// The broker-owned staging directory (`<state_dir>/staging`) — NOT world-writable `/tmp`. The
    /// worker writes verified artifacts here; the broker re-hashes + installs from it.
    #[must_use]
    pub fn staging_dir(&self) -> PathBuf {
        self.state_dir.join("staging")
    }

    /// The Admin/SYSTEM-only last-known-good cache (`<state_dir>/lkg`) that rollback restores from.
    #[must_use]
    pub fn lkg_dir(&self) -> PathBuf {
        self.state_dir.join("lkg")
    }

    /// The Admin/SYSTEM-only apply directory (`<state_dir>/apply`) a native-package artifact is
    /// copied into before its OS installer runs — so the installer never reads the worker-writable
    /// staging path (SPEC §8.3).
    #[must_use]
    pub fn apply_dir(&self) -> PathBuf {
        self.state_dir.join("apply")
    }
}

/// The current wall-clock time as unix seconds (0 if the clock is before the epoch).
#[must_use]
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_and_lkg_live_under_the_state_dir_not_tmp() {
        // The staging + last-known-good dirs are broker-owned (under the Admin-only state dir),
        // NOT world-writable /tmp (SPEC §8.3, #504-E).
        let broker = Broker::with_paths(PathBuf::from("/var/lib/dig-updater"), PathBuf::from("x"));
        assert_eq!(
            broker.staging_dir(),
            PathBuf::from("/var/lib/dig-updater/staging")
        );
        assert_eq!(broker.lkg_dir(), PathBuf::from("/var/lib/dig-updater/lkg"));
    }

    #[test]
    fn guarded_paths_repair_owned_dirs_but_never_the_binary() {
        let broker = Broker::with_paths(PathBuf::from("/var/lib/dig-updater"), PathBuf::from("x"));
        let guarded = broker.guarded_paths();
        // The four managed dirs are repairable...
        for dir in [
            broker.state_dir(),
            &broker.staging_dir(),
            &broker.lkg_dir(),
            &broker.apply_dir(),
        ] {
            assert!(guarded
                .iter()
                .any(|(p, r)| p == dir && *r == Repair::IfOwned));
        }
        // ...and the beacon binary, if resolvable, is guarded Never.
        assert!(guarded
            .iter()
            .all(|(_, r)| *r == Repair::IfOwned || *r == Repair::Never));
    }

    #[test]
    fn run_pass_hardens_dirs_and_acl_checks_before_spawning() {
        // A full pass with a MISSING worker binary: the ACL self-check + managed-dir creation +
        // staging prep all run first, then the worker spawn fails closed. Proves the pre-spawn
        // wiring (ACL, harden, dir layout) without needing a real feed or the production key.
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(
            home.path().to_path_buf(),
            home.path().join("no-such-worker"),
        );
        let root = dig_updater_trust::beacon_root_verifying_key();
        let probe = pass::spawn_version_probe();
        let err = broker
            .run_pass(
                &root,
                vec![FeedSource::new("http://127.0.0.1:9/feed")],
                Sandbox::Inherit,
                &probe,
                &probe,
            )
            .expect_err("a missing worker binary must fail to spawn");
        assert!(matches!(err, BrokerError::Spawn(_)));
        // Every broker-owned dir was created before the spawn attempt.
        for dir in [broker.staging_dir(), broker.lkg_dir(), broker.apply_dir()] {
            assert!(dir.exists(), "{} created before spawn", dir.display());
        }
        // ...and each was HARDENED up front (on Unix that is exactly checkable — owner-only;
        // on Windows the same code path applies the icacls DACL). The lkg dir in particular must be
        // hardened before any snapshot lands in it (#504-E).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [
                broker.lkg_dir(),
                broker.apply_dir(),
                broker.state_dir().to_path_buf(),
            ] {
                let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
                assert_eq!(
                    mode & 0o077,
                    0,
                    "{} must be owner-only after the harden phase",
                    dir.display()
                );
            }
        }
    }

    #[test]
    fn manual_rollback_anchors_its_floor_to_the_persisted_trust_state() {
        // The manual rollback path must read the rollback floor from the PERSISTED trust state, not
        // from a caller-supplied value: the lkg record's digest is self-recorded, so a caller who
        // could also choose the floor could reinstate a below-floor (vulnerable) build (SPEC §9.5).
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));

        // Persist a trust state whose enforced floor is build 10_000.
        let store = TrustStateStore::at(broker.state_dir());
        let persisted = dig_updater_trust::TrustState {
            root_version: 1,
            sequence: 1,
            generated: 1,
            rollback_floor_build: 10_000,
        };
        store
            .save(&persisted, &LoadedState::initial())
            .expect("persist state");

        // Snapshot a cached build BELOW that persisted floor (build 9_000).
        let cache = LkgCache::at(broker.lkg_dir());
        let dest = home.path().join("bin").join("digstore");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"old-below-floor-binary").unwrap();
        cache
            .snapshot("digstore", &dest, Some(9_000))
            .expect("snapshot");

        // Rollback refuses it BECAUSE the persisted floor (10_000) outranks the cached build — even
        // though no floor was passed to `rollback()` at all.
        let err = broker
            .rollback()
            .expect_err("a below-persisted-floor cached build must be refused");
        assert!(matches!(err, BrokerError::RollbackFailed { .. }));
    }

    #[test]
    fn trust_error_converts_into_broker_error() {
        use dig_updater_trust::TrustError;
        let e: BrokerError = TrustError::DelegationSignatureInvalid.into();
        assert!(matches!(e, BrokerError::Trust(_)));
        assert!(e.to_string().contains("delegation"));
    }

    #[test]
    fn now_is_after_2020() {
        assert!(now_unix_secs() > 1_577_836_800); // 2020-01-01
    }
}
