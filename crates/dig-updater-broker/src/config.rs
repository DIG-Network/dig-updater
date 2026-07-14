//! Persisted beacon CONFIGURATION (SPEC §13.1): the update channel and the pause/resume state.
//!
//! `config.json` lives in the SAME Admin/SYSTEM-only state directory as `trust-state.json`
//! (`<state_dir>/config.json`), so it inherits the identical directory-level lock-down
//! ([`crate::secure::harden_state_dir`]) — mutating it (`channel set`, `pause`, `resume`) is an
//! ADMIN-WRITABLE operation, gated in practice by [`crate::elevation`] at the call site rather
//! than by a second copy of the same OS-permission logic.
//!
//! Unlike [`crate::state::TrustStateStore`], this store does NOT need to preserve unknown fields
//! across a load→save round-trip: the four trust-state marks feed anti-downgrade/anti-rollback
//! decisions, where a fleet-wide rollback to an older beacon must never destroy a newer field.
//! Channel/pause carry no such security invariant, so a plain, schema-versioned struct
//! ([`UpdaterConfig`]) is the simpler, equally-correct choice here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::BrokerError;
use crate::persist::write_json_atomic;
use crate::secure::harden_state_dir;

/// The current on-disk shape of [`UpdaterConfig`] (SPEC §13.1). Bump when a field is added so a
/// future reader can tell which fields to expect.
pub const CONFIG_SCHEMA: u32 = 1;

const CONFIG_FILE: &str = "config.json";

/// The update channel a beacon tracks. `Alpha` is the only channel the feed serves today (SPEC
/// §10.3); `Stable` is reserved for a future production release and is not yet actionable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// The nightly alpha channel — the only channel served today.
    #[default]
    Alpha,
    /// Reserved for the future production channel.
    Stable,
}

impl Channel {
    /// The wire/CLI token for this channel (`"alpha"` / `"stable"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Stable => "stable",
        }
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The persisted configuration a beacon consults before acting (SPEC §13.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdaterConfig {
    /// The on-disk schema version ([`CONFIG_SCHEMA`]).
    #[serde(default = "current_config_schema")]
    pub schema: u32,
    /// The update channel this beacon tracks.
    #[serde(default)]
    pub channel: Channel,
    /// Whether auto-updates are currently paused.
    #[serde(default)]
    pub paused: bool,
    /// When `paused` is set, an optional unix-seconds expiry after which the pause lapses on its
    /// own (a "snooze"); `None` means paused indefinitely, until an explicit `resume`.
    #[serde(default)]
    pub paused_until: Option<u64>,
}

fn current_config_schema() -> u32 {
    CONFIG_SCHEMA
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            schema: CONFIG_SCHEMA,
            channel: Channel::default(),
            paused: false,
            paused_until: None,
        }
    }
}

impl UpdaterConfig {
    /// Is auto-update paused RIGHT NOW, at `now` (unix seconds)?
    ///
    /// A pause with no `paused_until` stays in effect until an explicit `resume`. A pause WITH a
    /// `paused_until` is a snooze: once `now` reaches it, the pause lapses on its own — the
    /// caller need not "un-pause" a timed snooze for it to stop gating passes.
    #[must_use]
    pub fn is_paused_at(&self, now: u64) -> bool {
        self.paused && self.paused_until.is_none_or(|until| now < until)
    }
}

/// Reads and writes the persisted [`UpdaterConfig`] under a state directory.
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    /// A store rooted at `state_dir` (the file is `<state_dir>/config.json`).
    #[must_use]
    pub fn at(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(CONFIG_FILE),
        }
    }

    /// The path of the config file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the persisted config. A missing file yields [`UpdaterConfig::default`] (a fresh
    /// install has never paused or switched channel); a present-but-malformed file fails closed
    /// with [`BrokerError::StateCorrupt`] rather than silently discarding an operator's settings.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] on a read error other than "not found"; [`BrokerError::StateCorrupt`]
    /// if the file exists but is not valid [`UpdaterConfig`] JSON.
    pub fn load(&self) -> Result<UpdaterConfig, BrokerError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| BrokerError::StateCorrupt(format!("config: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UpdaterConfig::default()),
            Err(e) => Err(BrokerError::Io(e.to_string())),
        }
    }

    /// Persist `config` atomically, hardening the containing state directory first (so a
    /// standalone `channel set`/`pause`, run before the beacon has ever taken a full pass, still
    /// leaves the directory Admin/SYSTEM-only — SPEC §9.3).
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] on any create/harden/write/rename failure.
    pub fn save(&self, config: &UpdaterConfig) -> Result<(), BrokerError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| BrokerError::Io(e.to_string()))?;
            harden_state_dir(dir)?;
        }
        let bytes =
            serde_json::to_vec_pretty(config).map_err(|e| BrokerError::Io(e.to_string()))?;
        write_json_atomic(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ConfigStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ConfigStore::at(dir.path());
        (dir, store)
    }

    #[test]
    fn missing_file_loads_as_default() {
        let (_dir, store) = store();
        assert_eq!(store.load().expect("load"), UpdaterConfig::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let (_dir, store) = store();
        let config = UpdaterConfig {
            schema: CONFIG_SCHEMA,
            channel: Channel::Alpha,
            paused: true,
            paused_until: Some(1_700_000_000),
        };
        store.save(&config).expect("save");
        assert_eq!(store.load().expect("load"), config);
    }

    #[test]
    fn corrupt_config_fails_closed_not_reset() {
        let (dir, store) = store();
        std::fs::write(dir.path().join("config.json"), b"{ not json").unwrap();
        let err = store
            .load()
            .expect_err("corrupt config must not silently reset to defaults");
        assert!(matches!(err, BrokerError::StateCorrupt(_)));
    }

    #[test]
    fn an_older_reader_defaults_missing_fields_instead_of_rejecting() {
        // A config written before `paused_until` existed: an older/partial object still parses,
        // defaulting the field it doesn't recognize rather than failing closed (channel/pause
        // carries no anti-downgrade invariant, unlike the trust state — see the module doc).
        let (dir, store) = store();
        std::fs::write(
            dir.path().join("config.json"),
            br#"{"schema":1,"channel":"alpha","paused":false}"#,
        )
        .unwrap();
        let config = store.load().expect("load");
        assert_eq!(config.paused_until, None);
    }

    #[test]
    fn channel_display_and_as_str_use_the_wire_token() {
        assert_eq!(Channel::Alpha.as_str(), "alpha");
        assert_eq!(Channel::Stable.to_string(), "stable");
    }

    #[test]
    fn indefinite_pause_gates_at_every_future_time() {
        let config = UpdaterConfig {
            paused: true,
            paused_until: None,
            ..UpdaterConfig::default()
        };
        assert!(config.is_paused_at(0));
        assert!(config.is_paused_at(u64::MAX));
    }

    #[test]
    fn a_timed_pause_lapses_once_now_reaches_paused_until() {
        let config = UpdaterConfig {
            paused: true,
            paused_until: Some(100),
            ..UpdaterConfig::default()
        };
        assert!(config.is_paused_at(50), "still within the snooze window");
        assert!(
            !config.is_paused_at(100),
            "the snooze must lapse AT its own expiry, not linger past it"
        );
        assert!(!config.is_paused_at(200));
    }

    #[test]
    fn not_paused_never_gates_regardless_of_paused_until() {
        let config = UpdaterConfig {
            paused: false,
            paused_until: Some(u64::MAX),
            ..UpdaterConfig::default()
        };
        assert!(!config.is_paused_at(0));
    }
}
