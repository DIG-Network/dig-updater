#![warn(missing_docs)]

//! # dig-updater-broker — the privileged broker
//!
//! The broker is the **privileged** half of the beacon's two-process split (SPEC §8.3). It holds
//! the rights to persist the Admin/SYSTEM-only trust state and (in follow-ups) to replace on-disk
//! binaries, but it does NOT touch the network. Instead it spawns the **unprivileged**
//! [`dig_updater_worker`] to fetch + verify, receives only a verified plan back, and — in the
//! install path (#504-E) — applies installs behind a health gate and rolls back on failure.
//!
//! This crate implements the -D + -E + -F + -G surface: loading the persisted trust state,
//! spawning the worker with dropped privileges ([`sandbox`]), a **dry check**
//! ([`Broker::dry_check`]) that verifies without installing, and the full install path
//! ([`Broker::run_once_with_feed`]) — a single-instance lock ([`lock`]), ACL self-check,
//! independent re-verify under the pinned key, staging re-verify, silent per-OS install, health
//! gate, re-verified rollback ([`pass::Installer`]), and — always last — the beacon's own
//! self-update ([`selfupdate`]). The per-OS scheduler artifact that WAKES a pass daily lives in
//! [`scheduler`]; the operator-facing channel/pause CONFIG and the unprivileged STATUS mirror the
//! CLI (#504-G) is built on live in [`config`] and [`status`] (SPEC §13).
//!
//! ## Never trust the worker on the install path (SPEC §8.3)
//!
//! The worker is unprivileged and network-facing, so its report is treated as untrusted input:
//! before installing anything, the broker RE-VERIFIES the whole signature chain under its OWN
//! pinned root key ([`pass::Installer`] step 1) and re-hashes each staged artifact against the
//! re-verified digest immediately before it is applied. The trust state advances ONLY after a
//! component installs AND passes its health gate, and never before the state directory is hardened.
//!
//! ## Two DIFFERENT privilege bars: `state_dir` vs `status_dir` (SPEC §13)
//!
//! Every store this crate persists lives under one of two directories, each with the OPPOSITE
//! grant from the other — never mix them up:
//!
//! - [`Broker::state_dir`] — Admin/SYSTEM-only ([`secure::harden_state_dir`]): `trust-state.json`
//!   ([`state::TrustStateStore`]) and `config.json` ([`config::ConfigStore`]). Mutating either is
//!   a privileged act, gated by [`elevation::require_elevated`] at the CLI call site.
//! - [`Broker::status_dir`] — world-readable ([`secure::harden_public_status_path`]):
//!   `status.json` ([`status::StatusStore`]), a snapshot ANY identity may read without elevation.
//!
//! ## The `unsafe` in the workspace
//!
//! Privilege-dropping needs OS primitives, so [`sandbox`] uses `unsafe` (Unix `setuid`/`setgid`;
//! Windows restricted-token spawn). On Windows only, [`lock`] also uses `unsafe` for the
//! DACL-restricted named mutex (`CreateMutexW`/`ReleaseMutex`/`LocalFree` have no safe wrapper);
//! its Unix half is safe, built on the same `fs4` flock wrapper `dig-node-core` already uses, so
//! the beacon never grows a second hand-rolled unsafe locking primitive. Every other module — and
//! every other crate — is safe.

pub mod config;
pub mod elevation;
mod error;
mod hashing;
pub mod health;
pub mod install;
pub mod lock;
mod pass;
pub mod paths;
mod persist;
pub mod plan;
pub mod proc;
pub mod rollback;
pub mod sandbox;
pub mod scheduler;
pub mod secure;
mod selfupdate;
mod spawn;
pub mod state;
pub mod status;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dig_updater_trust::beacon_root_verifying_key;
use dig_updater_worker::{
    production_feed_ladder, FeedSource, Platform, WorkerReport, WorkerRequest,
};

// Re-exported so consumers (the CLI, tests) can read the enumeration/health probe's inputs +
// outputs without depending on `dig-release-resolver` directly — the broker owns that contract.
pub use dig_release_resolver::{DetectedVersion, UpdateAction};

use config::{Channel, ConfigStore, UpdaterConfig};
use status::{StatusContext, StatusSnapshot, StatusStore};

pub use error::BrokerError;
pub use health::VersionProbe;
pub use install::RetryPolicy;
pub use pass::{ComponentOutcome, ComponentResult, Installer, PassReport};
pub use plan::{
    Catalog, ComponentTarget, InstallMethod, Plan, PlannedComponent, BEACON_COMPONENT_NAME,
};
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

    /// A broker for a DRY check ([`Self::dry_check`]) — like [`Self::new`], but its state dir comes
    /// from [`paths::dry_check_state_dir`], so [`paths::STATE_DIR_ENV`] can point an UNELEVATED
    /// `dig-updater check` at a writable directory. A dry check never installs and never advances
    /// the trust state, so relocating its state dir is safe; the install/full-pass path
    /// ([`Self::new`]) stays pinned to the hardened default, keeping anti-rollback non-overridable.
    ///
    /// This is what lets the signed feed's end-to-end keystone verify UNELEVATED (#540): without a
    /// writable state dir the worker cannot create its staging directory, and a valid, correctly
    /// signed feed comes back as a `staging_io_error` rejection rather than a verified verdict.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] if the worker binary path cannot be resolved.
    pub fn for_dry_check() -> Result<Self, BrokerError> {
        Ok(Self {
            state_dir: paths::dry_check_state_dir(),
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

    /// The state directory this broker reads/writes (Admin/SYSTEM-only — `trust-state.json` +
    /// `config.json`).
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// The WORLD-READABLE status directory this broker's `status.json` lives under — a
    /// [`paths::sibling_status_dir`] of [`Self::state_dir`], never nested inside it (SPEC §13.2).
    #[must_use]
    pub fn status_dir(&self) -> PathBuf {
        paths::sibling_status_dir(&self.state_dir)
    }

    /// Run a **dry** update check: load the persisted trust state, spawn the unprivileged worker
    /// to fetch + verify the feed and stage the artifacts, and return its report. This performs
    /// NO install and NEVER advances the trust state (SPEC §9 step 7 gates advancement on a
    /// health-checked install, which is #504-E). Also refreshes the unprivileged status mirror
    /// (SPEC §13.2) — best-effort; a failure to write it never fails the check itself.
    ///
    /// # Errors
    ///
    /// [`BrokerError`] if the state cannot be loaded or the worker cannot be run.
    pub fn dry_check(&self, feed_sources: Vec<FeedSource>) -> Result<WorkerReport, BrokerError> {
        let loaded = TrustStateStore::at(&self.state_dir).load()?;
        let report = self.fetch_and_verify(feed_sources, loaded.state, Sandbox::Restricted)?;
        // The config read here is PURELY for the status mirror (channel/paused to report) — a
        // corrupt/unreadable config must never fail an otherwise-successful dry check, so it
        // degrades to the default rather than propagating (contrast `run_once_with_feed`, where
        // the SAME read gates a real pass and so fails closed).
        let config = ConfigStore::at(&self.state_dir).load().unwrap_or_default();
        self.refresh_status_after_check(&report, &config, now_unix_secs(), loaded.state);
        Ok(report)
    }

    /// Run exactly one FULL update pass against the production feed ladder — the entry point the
    /// daily scheduler artifact invokes. See [`Self::run_once_with_feed`] for the full contract.
    ///
    /// # Errors
    ///
    /// See [`Self::run_once_with_feed`].
    pub fn run_once(&self) -> Result<PassReport, BrokerError> {
        self.run_once_with_feed(production_feed_ladder())
    }

    /// Run exactly one FULL update pass against an explicit feed ladder: single-instance lock →
    /// the pause gate → ACL self-check → spawn the unprivileged worker to fetch + verify + stage →
    /// INDEPENDENTLY re-verify under the pinned key → enumerate → silent per-OS install behind a
    /// health gate → re-verified rollback on failure → advance the trust state only on full
    /// success → the beacon's own self-update, always last. This is the beacon's production entry
    /// point (SPEC §8.2, §9, §9.5) — the one a scheduled wake, a manual `dig-updater run`, or
    /// `check --now` (#504-G) invokes. [`Self::run_once`] is this with the production ladder;
    /// threading the feed sources through here is what lets the CLI's `--feed-base` override apply
    /// to EITHER caller without bypassing any of this gating.
    ///
    /// If a prior pass is still holding the lock (its schedule overran), this returns a
    /// [`PassReport::already_running`] immediately rather than an error — SPEC §8.2 makes that an
    /// ordinary, expected outcome, not a failure. Likewise, if auto-updates are currently paused
    /// ([`config::UpdaterConfig::is_paused_at`]), this returns [`PassReport::paused`] before the
    /// network or the ACL self-check are ever touched (SPEC §13.1) — a paused beacon's scheduled
    /// OR on-demand pass no-ops exactly like an overrun one.
    ///
    /// Also refreshes the unprivileged status mirror (SPEC §13.2) with the pass's outcome —
    /// best-effort; a failure to write it never fails the pass itself.
    ///
    /// # Errors
    ///
    /// [`BrokerError::StateCorrupt`] if the persisted config is unreadable (the pause gate fails
    /// CLOSED rather than silently proceeding un-paused); [`BrokerError::AclViolation`] if a
    /// guarded path is unsafely writable; [`BrokerError::Spawn`] if the worker cannot be run;
    /// [`BrokerError::ReverifyFailed`] / [`BrokerError::StagingReverifyFailed`] if the worker's
    /// plan fails the broker's independent re-verification; [`BrokerError::RollbackFailed`] if a
    /// rollback cannot complete; [`BrokerError::Io`] on a filesystem error.
    pub fn run_once_with_feed(
        &self,
        feed_sources: Vec<FeedSource>,
    ) -> Result<PassReport, BrokerError> {
        // Acquired before ANY other work, per SPEC §8.2 — including before `run_pass`'s own
        // harden-then-ACL-check step. On Unix this is safe because the lock creates `state_dir`
        // itself, owner-only, on first touch (see `lock::imp::create_dir_owner_only`) rather than
        // depending on a later, separate harden call to close what would otherwise be a brief
        // insecure-permissions window.
        let Some(_guard) = lock::SingleInstanceLock::try_acquire(&self.state_dir)? else {
            return Ok(PassReport::already_running());
        };

        // The pause gate runs next, still before the network or the ACL self-check are touched
        // (SPEC §13.1). Unlike `dry_check`'s status-only config read, this one GATES a real pass,
        // so a corrupt config fails closed (`?`) instead of silently defaulting to "not paused".
        let config = ConfigStore::at(&self.state_dir).load()?;
        let now = now_unix_secs();
        if config.is_paused_at(now) {
            let report = PassReport::paused(config.paused_until);
            self.refresh_status_after_pass(&report, &config, now);
            return Ok(report);
        }

        let root = beacon_root_verifying_key();
        let probe = pass::spawn_version_probe();
        let report = self.run_pass(&root, feed_sources, Sandbox::Restricted, &probe, &probe)?;
        self.refresh_status_after_pass(&report, &config, now_unix_secs());
        Ok(report)
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

    /// Read the beacon's unprivileged status mirror (SPEC §13.2) — safe for ANY identity, no
    /// elevation. Never errors on "nothing recorded yet"
    /// ([`status::StatusSnapshot::never_checked`]); only a readable-but-corrupt file is a real
    /// error.
    ///
    /// # Errors
    ///
    /// [`BrokerError::StateCorrupt`] if a status file exists but is not valid JSON.
    pub fn status(&self) -> Result<StatusSnapshot, BrokerError> {
        StatusStore::at(&self.status_dir()).load()
    }

    /// The currently-configured update channel, read via the unprivileged [`Self::status`] mirror
    /// — so `channel get` (like `status`) never requires elevation (SPEC §13.1).
    ///
    /// # Errors
    ///
    /// [`BrokerError::StateCorrupt`] if the status mirror exists but is not valid JSON.
    pub fn channel(&self) -> Result<Channel, BrokerError> {
        Ok(self.status()?.channel)
    }

    /// Set the update channel. This mutates the Admin-writable `config.json` and so REQUIRES
    /// elevation (SPEC §13.1) — checked via the injected `is_elevated` (production passes
    /// [`elevation::is_elevated`]; tests inject a fixed closure so both branches are deterministic
    /// regardless of the actual privilege of the `cargo test` process — see [`elevation::require`]).
    ///
    /// # Errors
    ///
    /// A [`BrokerError::Io`] elevation failure if `is_elevated()` returns `false`; otherwise
    /// whatever [`config::ConfigStore::load`]/[`config::ConfigStore::save`] can fail with.
    pub fn set_channel(
        &self,
        channel: Channel,
        is_elevated: impl FnOnce() -> bool,
    ) -> Result<UpdaterConfig, BrokerError> {
        self.mutate_config(is_elevated, |config| config.channel = channel)
    }

    /// Pause auto-updates, optionally until a unix-seconds deadline (a "snooze" — SPEC §13.1); a
    /// paused beacon's next `run`/`check --now` no-ops ([`PassReport::paused`]) instead of acting.
    /// Requires elevation; see [`Self::set_channel`] for the `is_elevated` contract.
    ///
    /// # Errors
    ///
    /// See [`Self::set_channel`].
    pub fn pause(
        &self,
        until: Option<u64>,
        is_elevated: impl FnOnce() -> bool,
    ) -> Result<UpdaterConfig, BrokerError> {
        self.mutate_config(is_elevated, |config| {
            config.paused = true;
            config.paused_until = until;
        })
    }

    /// Resume auto-updates (clears the pause, SPEC §13.1). Requires elevation; see
    /// [`Self::set_channel`] for the `is_elevated` contract.
    ///
    /// # Errors
    ///
    /// See [`Self::set_channel`].
    pub fn resume(&self, is_elevated: impl FnOnce() -> bool) -> Result<UpdaterConfig, BrokerError> {
        self.mutate_config(is_elevated, |config| {
            config.paused = false;
            config.paused_until = None;
        })
    }

    /// The shared skeleton every config mutation follows: require elevation, load, apply `edit`,
    /// persist, and immediately refresh the unprivileged status mirror so a subsequent
    /// unprivileged `status`/`channel get` reflects the change without waiting for the next
    /// check/run (SPEC §13.1, §13.2).
    fn mutate_config(
        &self,
        is_elevated: impl FnOnce() -> bool,
        edit: impl FnOnce(&mut UpdaterConfig),
    ) -> Result<UpdaterConfig, BrokerError> {
        elevation::require(is_elevated)?;
        let store = ConfigStore::at(&self.state_dir);
        let mut config = store.load()?;
        edit(&mut config);
        store.save(&config)?;
        self.refresh_status_after_config_change(&config);
        Ok(config)
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

    /// Persist the status mirror produced by a DRY check.
    fn refresh_status_after_check(
        &self,
        report: &WorkerReport,
        config: &UpdaterConfig,
        now: u64,
        trust_state: dig_updater_trust::TrustState,
    ) {
        let ctx = StatusContext {
            config,
            now,
            next_wake: self.estimate_next_wake(now),
            trust_state,
        };
        self.write_status_best_effort(&StatusSnapshot::from_dry_check(report, &ctx));
    }

    /// Persist the status mirror produced by a FULL pass, re-reading the trust state so a
    /// just-advanced set of marks (a successful install) is reflected immediately.
    fn refresh_status_after_pass(&self, report: &PassReport, config: &UpdaterConfig, now: u64) {
        let trust_state = TrustStateStore::at(&self.state_dir)
            .load()
            .map(|loaded| loaded.state)
            .unwrap_or_default();
        let ctx = StatusContext {
            config,
            now,
            next_wake: self.estimate_next_wake(now),
            trust_state,
        };
        self.write_status_best_effort(&StatusSnapshot::from_pass(report, &ctx));
    }

    /// Immediately refresh the config-mirrored fields (channel/paused) after a config mutation —
    /// preserving everything else the last check/run reported, so `channel set`/`pause`/`resume`
    /// don't clobber `last_check`/`components` history with a config-only change.
    fn refresh_status_after_config_change(&self, config: &UpdaterConfig) {
        let mut snapshot = self
            .status()
            .unwrap_or_else(|_| StatusSnapshot::never_checked());
        snapshot.channel = config.channel;
        snapshot.paused = config.is_paused_at(now_unix_secs());
        snapshot.paused_until = config.paused_until;
        self.write_status_best_effort(&snapshot);
    }

    /// Persist `snapshot` to the world-readable status mirror. Best-effort: failing to write it
    /// must never fail an otherwise-successful check/run/config-change — only `state_dir` (the
    /// trust state, the config) is security-load-bearing; `status_dir` is informational (SPEC
    /// §13.2).
    fn write_status_best_effort(&self, snapshot: &StatusSnapshot) {
        if let Err(e) = StatusStore::at(&self.status_dir()).save(snapshot) {
            eprintln!("dig-updater: warning: could not refresh status.json: {e}");
        }
    }

    /// A best-effort ESTIMATE of the beacon's next scheduled wake: `now` plus one day if the daily
    /// schedule artifact ([`scheduler`]) is registered, else `None`. This is `now + 24h`, not a
    /// parse of the OS scheduler's own next-run time — good enough for an observability mirror,
    /// not a promise of the exact wake instant (the real artifact also jitters, SPEC §8.4).
    fn estimate_next_wake(&self, now: u64) -> Option<u64> {
        const ONE_DAY_SECS: u64 = 24 * 60 * 60;
        scheduler::status()
            .ok()
            .filter(|status| status.installed)
            .map(|_| now + ONE_DAY_SECS)
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
    fn for_dry_check_honors_the_state_dir_env_override() {
        // #540: the fix that lets an UNELEVATED `check` (e.g. the signed-feed keystone) run against
        // a writable state dir instead of the Admin-only default. No other test reads this env, so
        // setting it here does not race the parallel suite.
        let override_dir = tempfile::tempdir().expect("override dir");
        std::env::set_var(paths::STATE_DIR_ENV, override_dir.path());
        let broker = Broker::for_dry_check().expect("resolves the sibling worker binary");
        assert_eq!(broker.state_dir(), override_dir.path());
        std::env::remove_var(paths::STATE_DIR_ENV);

        // With the override cleared, it falls back to the hardened OS default — the install path is
        // never relocatable.
        assert_eq!(
            Broker::for_dry_check().expect("resolves").state_dir(),
            paths::default_state_dir()
        );
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

    #[test]
    #[ignore = "the production lock's Administrators/SYSTEM-only DACL (lock.rs) means only an \
                elevated console can even OPEN it to probe contention; run explicitly (`cargo \
                test -- --ignored`) from an elevated console, or via the elevated scheduler CI job"]
    fn run_once_exits_immediately_when_the_lock_is_already_held() {
        // A prior pass (or a manual run racing the schedule) still holds the production lock —
        // `run_once` must report `already_running` (SPEC §8.2) rather than attempting to spawn
        // the worker / touch the network at all.
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));
        let _held = lock::SingleInstanceLock::try_acquire(broker.state_dir())
            .expect("acquire the production lock")
            .expect("the lock starts unheld");

        let report = broker
            .run_once()
            .expect("a held lock is a benign no-op, not an error");
        assert_eq!(report, PassReport::already_running());
    }

    #[test]
    #[ignore = "acquires the SAME production single-instance lock as \
                `run_once_exits_immediately_when_the_lock_is_already_held` — Windows requires an \
                elevated console just to open the `Global\\` mutex; run via `-- --ignored` in the \
                elevated scheduler CI job"]
    fn a_paused_beacon_no_ops_without_ever_spawning_the_worker() {
        // Proves the REAL wiring (SPEC §13.1): `run_once` consults the persisted pause state
        // BEFORE the network or the ACL self-check are touched, so a missing worker binary never
        // even gets attempted while paused. The pause logic itself, and the elevation gate on
        // `pause()`, are unit-tested below WITHOUT the lock (`pause_requires_elevation` etc.).
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(
            home.path().to_path_buf(),
            home.path().join("no-such-worker"),
        );
        broker
            .pause(None, || true)
            .expect("pause (elevated in this test)");

        let report = broker
            .run_once()
            .expect("a paused beacon must no-op, not error, even with a missing worker binary");
        assert!(!report.applied);
        assert_eq!(report.reason.as_deref(), Some("paused"));
    }

    // -- config mutations: elevation-gated, and independent of the single-instance lock ---------
    //
    // Unlike `run_once`, `pause`/`resume`/`set_channel` never touch `lock::SingleInstanceLock`, so
    // these are ordinary, portable tests — no `#[ignore]`, no elevated CI job needed. This is what
    // proves "unprivileged pause/channel set fail cleanly (elevation required)".

    #[test]
    fn unelevated_pause_is_refused() {
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));
        let err = broker
            .pause(None, || false)
            .expect_err("pausing without elevation must be refused");
        assert!(matches!(err, BrokerError::Io(_)));
    }

    #[test]
    fn unelevated_resume_is_refused() {
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));
        let err = broker
            .resume(|| false)
            .expect_err("resuming without elevation must be refused");
        assert!(matches!(err, BrokerError::Io(_)));
    }

    #[test]
    fn unelevated_channel_set_is_refused() {
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));
        let err = broker
            .set_channel(Channel::Alpha, || false)
            .expect_err("setting the channel without elevation must be refused");
        assert!(matches!(err, BrokerError::Io(_)));
    }

    #[test]
    fn elevated_pause_persists_and_the_status_mirror_reflects_it_immediately() {
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));

        // `u64::MAX` stands in for "far enough in the future to never lapse during this test" —
        // an actual calendar timestamp would go stale as real time marches on.
        let config = broker
            .pause(Some(u64::MAX), || true)
            .expect("an elevated pause succeeds");
        assert!(config.paused);
        assert_eq!(config.paused_until, Some(u64::MAX));

        // The unprivileged status mirror reflects the pause WITHOUT waiting for a check/run.
        let status = broker
            .status()
            .expect("status is always unprivileged-readable");
        assert!(status.paused);
        assert_eq!(status.paused_until, Some(u64::MAX));
    }

    #[test]
    fn elevated_resume_clears_a_prior_pause() {
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));
        broker.pause(None, || true).expect("pause");

        let config = broker.resume(|| true).expect("an elevated resume succeeds");
        assert!(!config.paused);
        assert_eq!(config.paused_until, None);
        assert!(!broker.status().expect("status").paused);
    }

    #[test]
    fn status_and_channel_reads_never_require_elevation() {
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));
        // A fresh install: never checked, default channel — answerable with NO privilege probe.
        assert_eq!(broker.channel().expect("channel get"), Channel::Alpha);
        assert_eq!(
            broker.status().expect("status"),
            StatusSnapshot::never_checked()
        );
    }

    #[test]
    fn set_channel_updates_both_the_config_and_the_status_mirror() {
        let home = tempfile::tempdir().expect("home");
        let broker = Broker::with_paths(home.path().to_path_buf(), home.path().join("worker"));
        broker
            .set_channel(Channel::Alpha, || true)
            .expect("an elevated channel set succeeds");
        assert_eq!(broker.channel().expect("channel get"), Channel::Alpha);
    }
}
