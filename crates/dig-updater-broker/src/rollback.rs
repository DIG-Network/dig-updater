//! The last-known-good (LKG) cache and re-verified rollback (SPEC §9.5).
//!
//! Before replacing a component's binary, the broker SNAPSHOTS the current one into an
//! Admin/SYSTEM-only cache, recording its SHA-256 and packed build number. If the new build then
//! fails its health gate, the broker RESTORES the snapshot — but a rollback IS an install, so it
//! gets the same trust discipline:
//!
//! - the cached bytes are RE-HASHED against the digest recorded at snapshot time (never blindly
//!   copied back — a rollback must not reinstate corrupted or tampered bytes), and
//! - the cached build must be at or above the current `rollback_floor_build` (SPEC §9.5: a rollback
//!   MUST NOT downgrade below the floor — otherwise a health-induced rollback could re-open the
//!   very vulnerability the floor excludes).
//!
//! A fresh install (nothing at the destination yet) has no snapshot, so a failed fresh install is
//! rolled back by simply removing what was placed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::BrokerError;
use crate::hashing::{open_no_symlink, sha256_file};

/// The persisted record beside a cached binary, so a later manual [`crate::Broker::rollback`] can
/// re-verify + reinstate it across passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LkgRecord {
    /// Lowercase-hex SHA-256 of the cached bytes.
    digest: String,
    /// The cached build's packed number, if its version was parseable (`None` → un-ageable).
    build: Option<u64>,
    /// Where the binary is installed (the restore destination).
    dest: String,
}

/// One component's last-known-good snapshot: the cached bytes plus the facts needed to re-verify
/// and reinstate them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LkgEntry {
    /// The component name.
    pub component: String,
    /// Lowercase-hex SHA-256 recorded when the snapshot was taken.
    pub digest: String,
    /// The cached build's packed number (`None` if the prior version was unparseable).
    pub build: Option<u64>,
    /// The cached binary file inside the LKG cache.
    pub cached_path: PathBuf,
    /// The install destination this entry restores to.
    pub dest: PathBuf,
}

/// Which kind of rollback a [`LkgCache::restore`] is performing — this decides whether the
/// anti-downgrade floor gate applies.
///
/// The floor gate (SPEC §9.5) exists to stop a rollback from REINSTATING an OLDER, below-floor build
/// — re-opening a vulnerability the floor excludes. That risk only exists for a CROSS-PASS rollback,
/// where the cached bytes are a genuinely older build than what is (or was) installed. An IN-PASS
/// rollback restores the EXACT bytes snapshotted at the destination moments earlier in the SAME pass
/// (before the failed replace); reinstating them is a restore-in-place, never a downgrade relative to
/// itself, so it MUST bypass the floor gate — otherwise an un-ageable current build (`build == None`)
/// would leave `dest` missing on the double-rename-fault branch (#558).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreKind {
    /// Restore the just-captured current snapshot within the same pass — floor-EXEMPT (restoring the
    /// current-original bytes can never be a downgrade relative to itself).
    InPlace,
    /// Restore an older cached last-known-good build across passes — floor-GATED (anti-downgrade).
    CrossPass,
}

/// The Admin/SYSTEM-only last-known-good cache directory.
#[derive(Debug, Clone)]
pub struct LkgCache {
    dir: PathBuf,
}

impl LkgCache {
    /// A cache rooted at `dir` (hardened by the caller before first use).
    #[must_use]
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Snapshot the binary currently at `dest` (if any) into the cache, recording its digest and
    /// packed `build`. Returns `None` when nothing is installed there yet (a fresh install has no
    /// prior good build to keep).
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] if the cache cannot be written or the current binary cannot be read.
    pub fn snapshot(
        &self,
        component: &str,
        dest: &Path,
        build: Option<u64>,
    ) -> Result<Option<LkgEntry>, BrokerError> {
        if !dest.exists() {
            return Ok(None);
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| BrokerError::Io(e.to_string()))?;
        let digest = hex_lower(&sha256_file(dest)?);
        let cached_path = self.dir.join(component);
        copy_bytes(dest, &cached_path)?;
        let record = LkgRecord {
            digest: digest.clone(),
            build,
            dest: dest.display().to_string(),
        };
        let record_json =
            serde_json::to_vec_pretty(&record).map_err(|e| BrokerError::Io(e.to_string()))?;
        std::fs::write(self.record_path(component), record_json)
            .map_err(|e| BrokerError::Io(e.to_string()))?;
        Ok(Some(LkgEntry {
            component: component.to_string(),
            digest,
            build,
            cached_path,
            dest: dest.to_path_buf(),
        }))
    }

    /// Restore a snapshot after a failed health gate or a failed replace: RE-VERIFY the cached bytes
    /// against the recorded digest and — for a CROSS-PASS rollback only — the current `floor`, then
    /// reinstate them at the destination.
    ///
    /// `kind` decides whether the anti-downgrade floor gate applies. An [`RestoreKind::InPlace`]
    /// restore reinstates the current-original bytes captured earlier in the SAME pass, so it is
    /// floor-EXEMPT (restoring bytes onto their own destination can never be a downgrade relative to
    /// itself, and MUST succeed even when the prior build was un-ageable — #558, the double-rename
    /// fault). A [`RestoreKind::CrossPass`] restore reinstates a possibly-older cached build and stays
    /// floor-GATED (SPEC §9.5: a rollback MUST NOT downgrade below the floor).
    ///
    /// # Errors
    ///
    /// [`BrokerError::RollbackFailed`] if the cached bytes no longer match their recorded digest,
    /// if (cross-pass) the cached build is below `floor` or its age is unknown, or if the reinstate
    /// write fails — the worst case, needing operator attention.
    pub fn restore(
        &self,
        entry: &LkgEntry,
        floor: u64,
        kind: RestoreKind,
    ) -> Result<(), BrokerError> {
        // A cross-pass rollback must not downgrade below the floor (SPEC §9.5). An in-pass restore of
        // the just-captured current bytes is exempt — it is a restore-in-place, not a downgrade.
        if kind == RestoreKind::CrossPass {
            match entry.build {
                Some(build) if build >= floor => {}
                Some(build) => {
                    return Err(BrokerError::RollbackFailed {
                        component: entry.component.clone(),
                        detail: format!(
                            "cached build {build} is below the current rollback floor {floor}"
                        ),
                    })
                }
                None => {
                    return Err(BrokerError::RollbackFailed {
                        component: entry.component.clone(),
                        detail:
                            "cached build age is unknown; cannot prove it is at or above the floor"
                                .to_string(),
                    })
                }
            }
        }
        // Re-verify the cached bytes — a rollback is an install and gets the same digest gate.
        let computed = hex_lower(&sha256_file(&entry.cached_path).map_err(|e| {
            BrokerError::RollbackFailed {
                component: entry.component.clone(),
                detail: format!("cached bytes unreadable: {e}"),
            }
        })?);
        if computed != entry.digest {
            return Err(BrokerError::RollbackFailed {
                component: entry.component.clone(),
                detail: format!(
                    "cached bytes failed re-verification: expected {}, got {computed}",
                    entry.digest
                ),
            });
        }
        copy_bytes(&entry.cached_path, &entry.dest).map_err(|e| BrokerError::RollbackFailed {
            component: entry.component.clone(),
            detail: format!("reinstate write failed: {e}"),
        })
    }

    /// The sidecar record path for a component.
    fn record_path(&self, component: &str) -> PathBuf {
        self.dir.join(format!("{component}.json"))
    }

    /// Load a persisted entry for `component` (for a manual, cross-pass rollback).
    ///
    /// # Errors
    ///
    /// [`BrokerError::Io`] if the record is missing or malformed.
    pub fn load_entry(&self, component: &str) -> Result<LkgEntry, BrokerError> {
        let bytes = std::fs::read(self.record_path(component))
            .map_err(|e| BrokerError::Io(format!("no last-known-good for {component}: {e}")))?;
        let record: LkgRecord =
            serde_json::from_slice(&bytes).map_err(|e| BrokerError::Io(e.to_string()))?;
        Ok(LkgEntry {
            component: component.to_string(),
            digest: record.digest,
            build: record.build,
            cached_path: self.dir.join(component),
            dest: PathBuf::from(record.dest),
        })
    }

    /// The components with a persisted snapshot (for a manual rollback of the whole fleet).
    #[must_use]
    pub fn cached_components(&self) -> Vec<String> {
        std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.strip_suffix(".json").map(str::to_string)
            })
            .collect()
    }
}

/// Lowercase-hex encode a 32-byte digest (kept local so the crate needs no `hex` dependency).
fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Copy `src` to `dst` via a symlink-safe read + atomic sibling rename.
fn copy_bytes(src: &Path, dst: &Path) -> Result<(), BrokerError> {
    use std::io::{Read, Write};
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| BrokerError::Io(e.to_string()))?;
    }
    let mut file = open_no_symlink(src)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| BrokerError::Io(e.to_string()))?;
    let tmp = dst.with_extension("lkg-tmp");
    {
        let mut out = std::fs::File::create(&tmp).map_err(|e| BrokerError::Io(e.to_string()))?;
        out.write_all(&bytes)
            .map_err(|e| BrokerError::Io(e.to_string()))?;
        out.sync_all().map_err(|e| BrokerError::Io(e.to_string()))?;
    }
    std::fs::rename(&tmp, dst).map_err(|e| BrokerError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> (tempfile::TempDir, LkgCache) {
        let dir = tempfile::tempdir().unwrap();
        let cache = LkgCache::at(dir.path().join("lkg"));
        (dir, cache)
    }

    #[test]
    fn snapshot_of_a_missing_dest_is_none() {
        let (dir, cache) = cache();
        let entry = cache
            .snapshot("digstore", &dir.path().join("nope"), Some(15_000))
            .unwrap();
        assert!(entry.is_none(), "a fresh install has nothing to snapshot");
    }

    #[test]
    fn snapshot_then_restore_round_trips_the_bytes() {
        let (dir, cache) = cache();
        let dest = dir.path().join("bin").join("digstore");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"good-old-binary").unwrap();

        let entry = cache
            .snapshot("digstore", &dest, Some(14_000))
            .unwrap()
            .expect("a snapshot exists");

        // Simulate a failed new install having overwritten the destination.
        std::fs::write(&dest, b"broken-new-binary").unwrap();

        cache
            .restore(&entry, 10_000, RestoreKind::CrossPass)
            .expect("rollback restores");
        assert_eq!(std::fs::read(&dest).unwrap(), b"good-old-binary");
    }

    #[test]
    fn restore_refuses_a_below_floor_cached_build() {
        let (dir, cache) = cache();
        let dest = dir.path().join("digstore");
        std::fs::write(&dest, b"old").unwrap();
        let entry = cache
            .snapshot("digstore", &dest, Some(9_000))
            .unwrap()
            .unwrap();
        // Current floor is 10_000; the cached build 9_000 is below it — a CROSS-PASS rollback to an
        // older cached build must refuse to reinstate it (anti-downgrade, SPEC §9.5).
        let err = cache
            .restore(&entry, 10_000, RestoreKind::CrossPass)
            .expect_err("a below-floor rollback target must be refused");
        assert!(matches!(err, BrokerError::RollbackFailed { .. }));
    }

    #[test]
    fn restore_refuses_an_unknown_age_cached_build() {
        let (dir, cache) = cache();
        let dest = dir.path().join("digstore");
        std::fs::write(&dest, b"old").unwrap();
        let entry = cache.snapshot("digstore", &dest, None).unwrap().unwrap();
        let err = cache
            .restore(&entry, 0, RestoreKind::CrossPass)
            .expect_err("an un-ageable cached build cannot be proven at/above the floor");
        assert!(matches!(err, BrokerError::RollbackFailed { .. }));
    }

    /// #558 (round 2): the IN-PASS restore of a just-captured snapshot is floor-EXEMPT, so an
    /// un-ageable prior build (`build == None`) is still reinstated even when the double-rename fault
    /// left `dest` MISSING. This is the narrow branch the round-1 fix missed: the cross-pass floor
    /// gate must NOT block a restore-in-place of the current-original bytes.
    #[test]
    fn in_pass_restore_reinstates_an_unageable_snapshot_even_when_dest_is_missing() {
        let (dir, cache) = cache();
        let dest = dir.path().join("bin").join("dig-dns");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"original-running-bytes").unwrap();

        // The prior build is un-ageable (a malformed-date nightly / unparseable core → build == None).
        let entry = cache
            .snapshot("dig-dns", &dest, None)
            .unwrap()
            .expect("the original target is snapshotted");

        // The double-rename fault leaves dest genuinely missing before the rollback fires.
        std::fs::remove_file(&dest).unwrap();
        assert!(!dest.exists());

        // The in-pass rollback restores it regardless of ageability — dest is never left missing.
        cache
            .restore(&entry, 10_000, RestoreKind::InPlace)
            .expect("an in-pass restore-in-place is floor-exempt");
        assert_eq!(std::fs::read(&dest).unwrap(), b"original-running-bytes");
    }

    #[test]
    fn restore_refuses_corrupted_cached_bytes() {
        let (dir, cache) = cache();
        let dest = dir.path().join("digstore");
        std::fs::write(&dest, b"good").unwrap();
        let entry = cache
            .snapshot("digstore", &dest, Some(15_000))
            .unwrap()
            .unwrap();
        // Corrupt the cached bytes after the snapshot recorded their digest.
        std::fs::write(&entry.cached_path, b"tampered-cache").unwrap();
        let err = cache
            .restore(&entry, 0, RestoreKind::InPlace)
            .expect_err("corrupted cache must not be reinstated");
        assert!(matches!(err, BrokerError::RollbackFailed { .. }));
    }

    #[test]
    fn persisted_entry_reloads_for_a_manual_rollback() {
        let (dir, cache) = cache();
        let dest = dir.path().join("digstore");
        std::fs::write(&dest, b"good").unwrap();
        cache.snapshot("digstore", &dest, Some(15_000)).unwrap();

        let reloaded = cache.load_entry("digstore").expect("record reloads");
        assert_eq!(reloaded.build, Some(15_000));
        assert_eq!(reloaded.dest, dest);
        assert_eq!(cache.cached_components(), vec!["digstore".to_string()]);
    }
}
