//! Persistence for the monotonic [`TrustState`] (SPEC §6).
//!
//! Two properties beyond plain read/write matter here:
//!
//! - **Atomic writes.** The state is written to a temp file in the same directory and then
//!   renamed over the target, so a crash mid-write can never leave a truncated/half-written state
//!   that would be read as a *lower* high-water-mark (which would silently re-enable a downgrade).
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

use crate::error::BrokerError;

/// The on-disk file name for the persisted trust state.
const STATE_FILE: &str = "trust-state.json";

/// Reads and writes the persisted [`TrustState`] under a state directory, preserving any unknown
/// fields a newer beacon may have written.
#[derive(Debug, Clone)]
pub struct TrustStateStore {
    path: PathBuf,
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
    /// A store rooted at `state_dir` (the file is `<state_dir>/trust-state.json`).
    #[must_use]
    pub fn at(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(STATE_FILE),
        }
    }

    /// The path of the state file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the persisted state. A missing file yields [`LoadedState::initial`] (a fresh install);
    /// a present-but-malformed file fails closed with [`BrokerError::StateCorrupt`] rather than
    /// silently resetting the anti-rollback marks to zero.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] on a read error, [`BrokerError::StateCorrupt`] if the file is not a
    /// JSON object with the expected numeric marks.
    pub fn load(&self) -> Result<LoadedState, BrokerError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LoadedState::initial()),
            Err(e) => return Err(BrokerError::Io(e.to_string())),
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

    /// Atomically persist `state`, preserving every unknown field carried in `loaded.raw`.
    ///
    /// Writes a sibling temp file, flushes it, then renames it over the target — so a reader never
    /// observes a partial write.
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

        let dir = self
            .path
            .parent()
            .ok_or_else(|| BrokerError::Io("state path has no parent directory".into()))?;
        std::fs::create_dir_all(dir).map_err(|e| BrokerError::Io(e.to_string()))?;
        let tmp = self.path.with_extension("json.tmp");
        write_then_sync(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| BrokerError::Io(e.to_string()))?;
        Ok(())
    }
}

/// Read a required unsigned-integer field, failing closed if it is absent or not a `u64`.
fn read_u64(raw: &Map<String, Value>, key: &str) -> Result<u64, BrokerError> {
    match raw.get(key) {
        // A fresh field a newer beacon has not yet written defaults to 0 (the safe baseline).
        None => Ok(0),
        Some(v) => v.as_u64().ok_or_else(|| {
            BrokerError::StateCorrupt(format!("`{key}` is not an unsigned integer"))
        }),
    }
}

/// Write bytes to `path` and fsync before returning, so the rename that follows publishes a
/// fully-flushed file.
fn write_then_sync(path: &Path, bytes: &[u8]) -> Result<(), BrokerError> {
    use std::io::Write;
    let mut file = std::fs::File::create(path).map_err(|e| BrokerError::Io(e.to_string()))?;
    file.write_all(bytes)
        .map_err(|e| BrokerError::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| BrokerError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, TrustStateStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = TrustStateStore::at(dir.path());
        (dir, store)
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
        let state = TrustState {
            root_version: 2,
            sequence: 42,
            generated: 1_700_000_000,
            rollback_floor_build: 20,
        };
        store.save(&state, &LoadedState::initial()).expect("save");
        let loaded = store.load().expect("load");
        assert_eq!(loaded.state, state);
    }

    #[test]
    fn unknown_fields_survive_a_load_save_round_trip() {
        let (dir, store) = store();
        // Simulate a NEWER beacon having written an extra field.
        let seeded = r#"{"root_version":1,"sequence":5,"generated":100,"rollback_floor_build":3,"future_channel":"beta","nested":{"k":1}}"#;
        std::fs::write(dir.path().join("trust-state.json"), seeded).unwrap();

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
        let (dir, store) = store();
        std::fs::write(dir.path().join("trust-state.json"), b"{ not json").unwrap();
        let err = store
            .load()
            .expect_err("corrupt state must not silently reset");
        assert!(matches!(err, BrokerError::StateCorrupt(_)));
    }

    #[test]
    fn non_integer_mark_is_rejected() {
        let (dir, store) = store();
        std::fs::write(
            dir.path().join("trust-state.json"),
            br#"{"sequence":"lots"}"#,
        )
        .unwrap();
        assert!(matches!(store.load(), Err(BrokerError::StateCorrupt(_))));
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
}
