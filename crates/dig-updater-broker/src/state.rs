//! Persistence for the monotonic [`TrustState`] (SPEC §6), **per channel**.
//!
//! Each tracked channel keeps its OWN state file — `trust-state-<channel>.json` (`trust-state-
//! nightly.json`, `trust-state-stable.json`) — in the same Admin/SYSTEM-only directory with the
//! identical hardening. This is the anti-rollback security core (#591 D5): because each channel's
//! high-water-marks live in a SEPARATE file that the pass only advances for the channel it is
//! tracking, a channel SWITCH can never rewind the OTHER channel's rollback floor — the two floors
//! are structurally independent. A newly-selected channel with no prior file starts fresh (its
//! first valid, UNEXPIRED manifest establishes the baseline, bounded by the absolute anti-freeze
//! expiry §7.1 — not by monotonic state, so an adversary cannot serve a >12h-stale manifest as that
//! baseline).
//!
//! **Legacy migration (nightly only).** The pre-channel beacon kept ONE `trust-state.json`. On the
//! first load after upgrade the NIGHTLY channel ADOPTS that legacy file (legacy alpha ≡ nightly,
//! #591 D3), so installs already on the bleeding-edge stream keep their monotonic marks with no
//! reset. STABLE has no legacy file and starts fresh. Once the per-channel file exists, the legacy
//! file is ignored (never written to again).
//!
//! Two properties beyond plain read/write matter here:
//!
//! - **Atomic writes.** [`crate::persist::write_json_atomic`] writes a temp file in the same
//!   directory and renames it over the target, so a crash mid-write can never leave a
//!   truncated/half-written state that would be read as a *lower* high-water-mark (which would
//!   silently re-enable a downgrade).
//! - **Forward-compatible.** A future beacon may add fields to the on-disk JSON. An older beacon
//!   that loads and re-saves the state MUST preserve those unknown fields verbatim, so rolling
//!   the fleet back to an older beacon never destroys state a newer one wrote (SPEC §9.5). We
//!   round-trip the full JSON object and only overwrite the known keys.
//!
//! Advancing the persisted marks happens ONLY after a health-gated install (SPEC §9 step 7); a
//! `check --dry-run` loads the state but never saves it.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use dig_updater_trust::TrustState;

use crate::config::Channel;
use crate::error::BrokerError;
use crate::persist::write_json_atomic;

/// The pre-channel state file the NIGHTLY channel adopts on first load (legacy alpha ≡ nightly,
/// #591 D3). Never written to once a per-channel file exists.
const LEGACY_STATE_FILE: &str = "trust-state.json";

/// The per-channel state file name for `channel` (`trust-state-nightly.json` / `trust-state-
/// stable.json`).
fn state_file_name(channel: Channel) -> String {
    format!("trust-state-{}.json", channel.as_str())
}

/// Reads and writes ONE channel's persisted [`TrustState`] under a state directory, preserving any
/// unknown fields a newer beacon may have written, and — for nightly — adopting the legacy
/// single-channel file on first load.
#[derive(Debug, Clone)]
pub struct TrustStateStore {
    /// The per-channel state file this store reads and writes.
    path: PathBuf,
    /// The legacy pre-channel `trust-state.json` to ADOPT when `path` is absent — `Some` for the
    /// nightly channel (which inherits the old single-channel state), `None` for stable (which
    /// starts fresh). Only ever READ; saves always target `path`.
    legacy_path: Option<PathBuf>,
}

/// A loaded trust state plus the raw JSON object it came from — the raw object carries any
/// unknown fields forward on the next [`TrustStateStore::save`].
#[derive(Debug, Clone)]
pub struct LoadedState {
    /// The four monotonic marks the verifier enforces.
    pub state: TrustState,
    /// The full on-disk object (known + unknown fields), preserved for a forward-compatible save.
    raw: Map<String, Value>,
}

impl LoadedState {
    /// The initial (fresh-install) state: all marks zero, no extra fields.
    #[must_use]
    pub fn initial() -> Self {
        Self {
            state: TrustState::initial(),
            raw: Map::new(),
        }
    }
}

impl TrustStateStore {
    /// A store for `channel`'s state under `state_dir` (the file is
    /// `<state_dir>/trust-state-<channel>.json`). The NIGHTLY store additionally adopts the legacy
    /// `<state_dir>/trust-state.json` on first load (alpha ≡ nightly migration, #591 D3); the
    /// STABLE store has no legacy fallback and starts fresh.
    #[must_use]
    pub fn for_channel(state_dir: &Path, channel: Channel) -> Self {
        Self {
            path: state_dir.join(state_file_name(channel)),
            legacy_path: match channel {
                Channel::Nightly => Some(state_dir.join(LEGACY_STATE_FILE)),
                Channel::Stable => None,
            },
        }
    }

    /// The path of the per-channel state file this store reads and writes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the persisted state. The per-channel file is preferred; when it is absent the NIGHTLY
    /// store falls back to the legacy `trust-state.json` (adopting the old single-channel marks,
    /// #591 D3). A wholly-absent state (no per-channel file, no adoptable legacy) yields
    /// [`LoadedState::initial`] (a fresh install / fresh channel — its first valid, unexpired
    /// manifest is the baseline). A present-but-malformed file fails closed with
    /// [`BrokerError::StateCorrupt`] rather than silently resetting the anti-rollback marks to zero.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] on a read error, [`BrokerError::StateCorrupt`] if the file is not a
    /// JSON object with the expected numeric marks.
    pub fn load(&self) -> Result<LoadedState, BrokerError> {
        let bytes = match self.read_state_bytes()? {
            Some(bytes) => bytes,
            None => return Ok(LoadedState::initial()),
        };
        let raw: Map<String, Value> =
            serde_json::from_slice(&bytes).map_err(|e| BrokerError::StateCorrupt(e.to_string()))?;
        let state = TrustState {
            root_version: read_u64(&raw, "root_version")?
                .try_into()
                .map_err(|_| BrokerError::StateCorrupt("root_version out of range".into()))?,
            sequence: read_u64(&raw, "sequence")?,
            generated: read_u64(&raw, "generated")?,
            rollback_floor_build: read_u64(&raw, "rollback_floor_build")?,
        };
        Ok(LoadedState { state, raw })
    }

    /// Read the raw state bytes to load: the per-channel file if present, else — for the nightly
    /// store — the legacy `trust-state.json` (migration adoption). `None` means no state exists to
    /// load (a fresh install / fresh channel), distinct from an I/O error. Only the WHOLE-file-
    /// absent case is a fresh baseline; a present file that later fails to parse fails closed.
    fn read_state_bytes(&self) -> Result<Option<Vec<u8>>, BrokerError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match &self.legacy_path {
                Some(legacy) => match std::fs::read(legacy) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(BrokerError::Io(e.to_string())),
                },
                None => Ok(None),
            },
            Err(e) => Err(BrokerError::Io(e.to_string())),
        }
    }

    /// Atomically persist `state`, preserving every unknown field carried in `loaded.raw`.
    ///
    /// Writes a sibling temp file, flushes it, then renames it over the target ([`write_json_atomic`])
    /// — so a reader never observes a partial write.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] on any write/rename error.
    pub fn save(&self, state: &TrustState, loaded: &LoadedState) -> Result<(), BrokerError> {
        // Start from the previously-loaded object so unknown fields survive, then overwrite the
        // four known marks with the advanced values.
        let mut object = loaded.raw.clone();
        object.insert("root_version".into(), Value::from(state.root_version));
        object.insert("sequence".into(), Value::from(state.sequence));
        object.insert("generated".into(), Value::from(state.generated));
        object.insert(
            "rollback_floor_build".into(),
            Value::from(state.rollback_floor_build),
        );
        let bytes = serde_json::to_vec_pretty(&Value::Object(object))
            .map_err(|e| BrokerError::Io(e.to_string()))?;
        write_json_atomic(&self.path, &bytes)
    }
}

/// Read a required monotonic mark, failing closed if it is absent or not a `u64`.
///
/// A mark that is MISSING from a state file that otherwise exists is treated as corruption, NOT as
/// a `0` default: the four marks have existed since the first on-disk format, so their absence
/// means the file was truncated or tampered with — and defaulting the missing mark to `0` would
/// silently lower an anti-rollback high-water-mark, re-enabling a downgrade (SPEC §6). A genuinely
/// fresh install is the WHOLE-file-absent case, handled in [`TrustStateStore::load`] before this
/// is ever reached. (Unknown EXTRA fields a newer beacon added are still carried forward verbatim
/// via `LoadedState::raw`; only the four known marks are required here.)
fn read_u64(raw: &Map<String, Value>, key: &str) -> Result<u64, BrokerError> {
    match raw.get(key) {
        None => Err(BrokerError::StateCorrupt(format!(
            "required mark `{key}` is missing from an existing state file"
        ))),
        Some(v) => v.as_u64().ok_or_else(|| {
            BrokerError::StateCorrupt(format!("`{key}` is not an unsigned integer"))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stable-channel store — the mechanics tests exercise the primary per-channel file directly
    /// (`store.path()`), independent of the nightly legacy-adoption path (tested separately below).
    fn store() -> (tempfile::TempDir, TrustStateStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TrustStateStore::for_channel(dir.path(), Channel::Stable);
        (dir, store)
    }

    fn a_state() -> TrustState {
        TrustState {
            root_version: 2,
            sequence: 42,
            generated: 1_700_000_000,
            rollback_floor_build: 20,
        }
    }

    #[test]
    fn missing_file_loads_as_initial() {
        let (_dir, store) = store();
        let loaded = store.load().expect("load");
        assert_eq!(loaded.state, TrustState::initial());
    }

    #[test]
    fn save_then_load_round_trips_the_marks() {
        let (_dir, store) = store();
        let state = a_state();
        store.save(&state, &LoadedState::initial()).expect("save");
        let loaded = store.load().expect("load");
        assert_eq!(loaded.state, state);
    }

    #[test]
    fn unknown_fields_survive_a_load_save_round_trip() {
        let (_dir, store) = store();
        // Simulate a NEWER beacon having written an extra field to this channel's file.
        let seeded = r#"{"root_version":1,"sequence":5,"generated":100,"rollback_floor_build":3,"future_channel":"beta","nested":{"k":1}}"#;
        std::fs::write(store.path(), seeded).unwrap();

        let loaded = store.load().expect("load");
        // An OLDER beacon advances the marks it understands...
        let advanced = TrustState {
            sequence: 6,
            ..loaded.state
        };
        store.save(&advanced, &loaded).expect("save");

        // ...and the unknown fields are preserved verbatim.
        let reread: Map<String, Value> =
            serde_json::from_slice(&std::fs::read(store.path()).unwrap()).unwrap();
        assert_eq!(reread["future_channel"], Value::from("beta"));
        assert_eq!(reread["nested"]["k"], Value::from(1));
        assert_eq!(reread["sequence"], Value::from(6u64));
    }

    #[test]
    fn corrupt_state_fails_closed_not_reset() {
        let (_dir, store) = store();
        std::fs::write(store.path(), b"{ not json").unwrap();
        let err = store
            .load()
            .expect_err("corrupt state must not silently reset");
        assert!(matches!(err, BrokerError::StateCorrupt(_)));
    }

    #[test]
    fn existing_file_missing_a_known_mark_fails_closed() {
        // A state file that EXISTS but lacks a known mark is corruption/tampering — NOT a fresh
        // install. Defaulting the missing mark to 0 would silently lower an anti-rollback
        // high-water-mark (SPEC §6), so it must fail closed instead.
        let (_dir, store) = store();
        std::fs::write(
            store.path(),
            // `sequence` is deliberately omitted.
            br#"{"root_version":1,"generated":100,"rollback_floor_build":3}"#,
        )
        .unwrap();
        let err = store
            .load()
            .expect_err("a missing mark must not default to 0");
        assert!(matches!(err, BrokerError::StateCorrupt(_)));
        assert!(err.to_string().contains("sequence"));
    }

    #[test]
    fn non_integer_mark_is_rejected() {
        let (_dir, store) = store();
        // All four marks present, but `sequence` is a string — a corrupt value, not a missing one.
        std::fs::write(
            store.path(),
            br#"{"root_version":1,"sequence":"lots","generated":100,"rollback_floor_build":3}"#,
        )
        .unwrap();
        let err = store
            .load()
            .expect_err("a non-integer mark must be rejected");
        assert!(matches!(err, BrokerError::StateCorrupt(_)));
        assert!(err.to_string().contains("not an unsigned integer"));
    }

    #[test]
    fn save_is_atomic_leaving_no_temp_file() {
        let (dir, store) = store();
        store
            .save(&TrustState::initial(), &LoadedState::initial())
            .expect("save");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file should remain after save"
        );
    }

    // -- per-channel file naming + isolation (the anti-rollback security core, #591 D5) ----------

    #[test]
    fn each_channel_uses_its_own_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let nightly = TrustStateStore::for_channel(dir.path(), Channel::Nightly);
        let stable = TrustStateStore::for_channel(dir.path(), Channel::Stable);
        assert!(nightly.path().ends_with("trust-state-nightly.json"));
        assert!(stable.path().ends_with("trust-state-stable.json"));
        assert_ne!(nightly.path(), stable.path());
    }

    #[test]
    fn a_switch_can_never_rewind_the_other_channels_floor() {
        // The core invariant: advancing ONE channel's high-water-marks leaves the OTHER channel's
        // file — and therefore its rollback floor — exactly where it was. Because the two channels
        // persist to SEPARATE files, a stable→nightly→stable switch cannot lower either floor.
        let dir = tempfile::tempdir().unwrap();
        let nightly = TrustStateStore::for_channel(dir.path(), Channel::Nightly);
        let stable = TrustStateStore::for_channel(dir.path(), Channel::Stable);

        // Establish a HIGH stable floor, then a lower-numbered nightly state (different scales).
        stable
            .save(
                &TrustState {
                    root_version: 3,
                    sequence: 900,
                    generated: 1_000_000,
                    rollback_floor_build: 31_001,
                },
                &LoadedState::initial(),
            )
            .unwrap();
        nightly
            .save(
                &TrustState {
                    root_version: 1,
                    sequence: 20,
                    generated: 500_000,
                    rollback_floor_build: 20_260_101,
                },
                &LoadedState::initial(),
            )
            .unwrap();

        // Advancing nightly again must not touch the stable file at all.
        let loaded_nightly = nightly.load().unwrap();
        nightly
            .save(
                &TrustState {
                    sequence: 21,
                    ..loaded_nightly.state
                },
                &loaded_nightly,
            )
            .unwrap();

        // The stable floor is untouched — a switch away and back cannot lower it.
        assert_eq!(stable.load().unwrap().state.rollback_floor_build, 31_001);
        assert_eq!(stable.load().unwrap().state.sequence, 900);
        // ...and the nightly floor is likewise its own, on its own (date) scale.
        assert_eq!(
            nightly.load().unwrap().state.rollback_floor_build,
            20_260_101
        );
        assert_eq!(nightly.load().unwrap().state.sequence, 21);
    }

    // -- legacy migration: alpha ≡ nightly adopts trust-state.json (#591 D3) ----------------------

    #[test]
    fn nightly_adopts_the_legacy_trust_state_on_first_load() {
        // A pre-channel beacon left a single `trust-state.json`; upgrading, the NIGHTLY channel
        // adopts it (alpha ≡ nightly) so an install already on the bleeding-edge stream keeps its
        // monotonic marks with no reset.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(LEGACY_STATE_FILE),
            br#"{"root_version":2,"sequence":777,"generated":1234567,"rollback_floor_build":42}"#,
        )
        .unwrap();

        let nightly = TrustStateStore::for_channel(dir.path(), Channel::Nightly);
        let adopted = nightly.load().expect("legacy state adopted").state;
        assert_eq!(adopted.sequence, 777);
        assert_eq!(adopted.rollback_floor_build, 42);

        // Once nightly SAVES, it writes its OWN per-channel file; the legacy file is never touched.
        nightly.save(&adopted, &LoadedState::initial()).unwrap();
        assert!(nightly.path().exists(), "per-channel file is written");
    }

    #[test]
    fn stable_starts_fresh_ignoring_a_legacy_trust_state() {
        // Legacy state was the alpha (≡ nightly) stream. A fresh STABLE channel MUST NOT inherit
        // it — it starts from initial and lets its first valid, unexpired manifest be the baseline
        // (bounded by anti-freeze §7.1, not by adopted marks).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(LEGACY_STATE_FILE),
            br#"{"root_version":2,"sequence":777,"generated":1234567,"rollback_floor_build":42}"#,
        )
        .unwrap();

        let stable = TrustStateStore::for_channel(dir.path(), Channel::Stable);
        assert_eq!(
            stable.load().expect("fresh stable").state,
            TrustState::initial(),
            "stable must not adopt the legacy alpha/nightly state"
        );
    }

    #[test]
    fn the_per_channel_file_wins_over_the_legacy_file_once_it_exists() {
        // After migration the nightly per-channel file is authoritative; a stale legacy file left
        // behind must NOT shadow it (which could otherwise re-present older, lower marks).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(LEGACY_STATE_FILE),
            br#"{"root_version":1,"sequence":1,"generated":1,"rollback_floor_build":1}"#,
        )
        .unwrap();
        let nightly = TrustStateStore::for_channel(dir.path(), Channel::Nightly);
        // Advance the per-channel file well past the legacy marks.
        nightly.save(&a_state(), &LoadedState::initial()).unwrap();

        assert_eq!(
            nightly.load().unwrap().state,
            a_state(),
            "the per-channel file, not the stale legacy file, is authoritative once it exists"
        );
    }
}
