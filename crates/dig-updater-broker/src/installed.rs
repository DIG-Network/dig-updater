//! What build of each component this beacon last INSTALLED, per channel (dig_ecosystem#1858).
//!
//! A component whose installed version is established by hashing (a
//! [`ArtifactDigest`](crate::plan::VersionEvidence::ArtifactDigest) component) can only ever answer
//! one of two things about the file on disk: "it is the build the manifest promises" or "it is
//! something else". A NEWER build than the feed's is indistinguishable from an older one — both are
//! simply "not this digest" — so a host running ahead of the feed was planned as an Update and pushed
//! BACKWARDS onto the feed's build. The shared decision matrix cannot fix that from the outside:
//! `dig-release-resolver` is an external crate whose digest path has no version to compare.
//!
//! So the beacon remembers, on its own side, which build it installed. The guard then sits on the
//! resolver's OUTPUT ([`guard_newer_installed`](crate::plan::guard_newer_installed)) and can only ever
//! turn an Update into a Skip.
//!
//! Three deliberate choices:
//!
//! - **A SEPARATE file, never a key inside `trust-state-<channel>.json`.** That reader is the
//!   fail-closed anti-rollback security core: a missing or malformed mark there is treated as tampering
//!   and refuses the pass ([`crate::state`]). A component→build map is observability, not trust, and a
//!   problem with it must never escalate into trust-state corruption.
//! - **Loading is INFALLIBLE.** An absent or corrupt file loads as EMPTY (with a warning), which plans
//!   exactly as a beacon that had never recorded anything: every component is decided by its evidence
//!   as before. Failing closed here would let one unreadable JSON file stop a host updating at all —
//!   the inverse of what the file is for.
//! - **The recorded value is the build ACTUALLY PRESENT, not a high-water mark.** A rollback
//!   re-records the REINSTATED build (or removes the entry when there was none), because a high-water
//!   mark would remember a build that is no longer on disk and skip the install that would restore it —
//!   stranding the host on the rolled-back build forever.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::Channel;
use crate::error::BrokerError;
use crate::persist::write_json_atomic;

/// The per-channel record file name (`installed-builds-stable.json`).
fn installed_builds_file_name(channel: Channel) -> String {
    format!("installed-builds-{}.json", channel.as_str())
}

/// The builds this beacon last installed, by component name. An absent entry means "this beacon has
/// not installed that component", which is the state every host starts in and is never an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstalledBuilds(BTreeMap<String, u64>);

impl InstalledBuilds {
    /// The build this beacon last installed for `component`, if it has installed one.
    #[must_use]
    pub fn build_of(&self, component: &str) -> Option<u64> {
        self.0.get(component).copied()
    }

    /// A record set built from explicit pairs — for tests and for callers that already hold the map.
    #[must_use]
    pub fn from_pairs<I, S>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (S, u64)>,
        S: Into<String>,
    {
        Self(
            pairs
                .into_iter()
                .map(|(name, build)| (name.into(), build))
                .collect(),
        )
    }
}

/// Reads and writes ONE channel's [`InstalledBuilds`] under the Admin/SYSTEM-only state directory
/// (already hardened by [`crate::secure::harden_state_dir`] before any pass writes here).
#[derive(Debug, Clone)]
pub struct InstalledBuildStore {
    path: PathBuf,
}

impl InstalledBuildStore {
    /// A store for `channel`'s records under `state_dir` (the file is
    /// `<state_dir>/installed-builds-<channel>.json`).
    #[must_use]
    pub fn for_channel(state_dir: &Path, channel: Channel) -> Self {
        Self {
            path: state_dir.join(installed_builds_file_name(channel)),
        }
    }

    /// The path of the record file this store reads and writes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the recorded builds. Infallible BY DESIGN (see the module doc): an absent file, an
    /// unreadable one, or malformed JSON all yield an EMPTY set — warned about, never fatal.
    #[must_use]
    pub fn load(&self) -> InstalledBuilds {
        let Ok(bytes) = std::fs::read(&self.path) else {
            return InstalledBuilds::default();
        };
        match serde_json::from_slice::<BTreeMap<String, u64>>(&bytes) {
            Ok(map) => InstalledBuilds(map),
            Err(e) => {
                eprintln!(
                    "dig-updater: warning: {} is not a readable component→build map ({e}); \
                     planning as if nothing had been recorded",
                    self.path.display()
                );
                InstalledBuilds::default()
            }
        }
    }

    /// Record the build `component` now ACTUALLY has installed — or, with `build == None`, forget it
    /// (nothing of ours is on disk there any more).
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] if the record file cannot be written.
    pub fn record(&self, component: &str, build: Option<u64>) -> Result<(), BrokerError> {
        let InstalledBuilds(mut map) = self.load();
        match build {
            Some(build) => {
                map.insert(component.to_string(), build);
            }
            None => {
                map.remove(component);
            }
        }
        let bytes = serde_json::to_vec_pretty(&map).map_err(|e| BrokerError::Io(e.to_string()))?;
        write_json_atomic(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, InstalledBuildStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = InstalledBuildStore::for_channel(dir.path(), Channel::Stable);
        (dir, store)
    }

    #[test]
    fn an_absent_or_corrupt_installed_builds_file_loads_as_empty() {
        let (_dir, store) = store();
        assert_eq!(store.load(), InstalledBuilds::default(), "absent → empty");

        std::fs::write(store.path(), b"{not json at all").expect("write");
        assert_eq!(
            store.load(),
            InstalledBuilds::default(),
            "corrupt → empty, NOT an error: one unreadable observability file must never stop a host \
             from updating"
        );
    }

    #[test]
    fn a_recorded_build_round_trips_per_component() {
        let (_dir, store) = store();
        store.record("dig-app", Some(3_004_000)).expect("record");
        store.record("digstore", Some(19_003)).expect("record");
        let loaded = store.load();
        assert_eq!(loaded.build_of("dig-app"), Some(3_004_000));
        assert_eq!(loaded.build_of("digstore"), Some(19_003));
        assert_eq!(
            loaded.build_of("dig-dns"),
            None,
            "an unrecorded component is None"
        );
    }

    #[test]
    fn recording_none_forgets_the_component_without_disturbing_the_others() {
        let (_dir, store) = store();
        store.record("dig-app", Some(3_004_000)).expect("record");
        store.record("digstore", Some(19_003)).expect("record");
        store.record("dig-app", None).expect("forget");
        let loaded = store.load();
        assert_eq!(
            loaded.build_of("dig-app"),
            None,
            "nothing of ours is installed there any more, so nothing is remembered"
        );
        assert_eq!(loaded.build_of("digstore"), Some(19_003));
    }

    #[test]
    fn each_channel_keeps_its_own_records() {
        // The two channels number their builds on DIFFERENT scales (packed semver vs a nightly
        // YYYYMMDD date), so a shared file would compare a stable build against a nightly one.
        let dir = tempfile::tempdir().expect("tempdir");
        let stable = InstalledBuildStore::for_channel(dir.path(), Channel::Stable);
        let nightly = InstalledBuildStore::for_channel(dir.path(), Channel::Nightly);
        assert_ne!(stable.path(), nightly.path());
        stable.record("dig-app", Some(3_004_000)).expect("record");
        assert_eq!(nightly.load().build_of("dig-app"), None);
    }
}
