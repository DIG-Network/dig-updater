//! Atomic JSON-file persistence, shared by every on-disk store in this crate
//! ([`crate::state::TrustStateStore`], [`crate::config::ConfigStore`], [`crate::status::StatusStore`]).
//!
//! Every store writes a sibling temp file, fsyncs it, then renames it over the target, so a
//! reader never observes a partial write and a crash mid-write can never leave a truncated file
//! that would be misread as a reset/default value.

use std::io::Write;
use std::path::Path;

use crate::error::BrokerError;

/// Write `bytes` to `path` atomically: create the parent directory if needed, write a `.json.tmp`
/// sibling, fsync it, then rename it over `path`.
///
/// # Errors
///
/// [`BrokerError::Io`] on any create/write/fsync/rename failure.
pub fn write_json_atomic(path: &Path, bytes: &[u8]) -> Result<(), BrokerError> {
    let dir = path
        .parent()
        .ok_or_else(|| BrokerError::Io("path has no parent directory".into()))?;
    std::fs::create_dir_all(dir).map_err(|e| BrokerError::Io(e.to_string()))?;
    let tmp = path.with_extension("json.tmp");
    write_then_sync(&tmp, bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| BrokerError::Io(e.to_string()))?;
    Ok(())
}

/// Write bytes to `path` and fsync before returning, so the rename that follows publishes a
/// fully-flushed file.
fn write_then_sync(path: &Path, bytes: &[u8]) -> Result<(), BrokerError> {
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

    #[test]
    fn write_json_atomic_creates_missing_parent_dirs() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("nested").join("deep").join("file.json");
        write_json_atomic(&path, b"{}").expect("write");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}");
    }

    #[test]
    fn write_json_atomic_leaves_no_temp_file_behind() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("file.json");
        write_json_atomic(&path, b"{}").expect("write");
        let leftovers: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no temp file should remain");
    }

    #[test]
    fn write_json_atomic_overwrites_an_existing_file() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("file.json");
        write_json_atomic(&path, b"{\"a\":1}").expect("first write");
        write_json_atomic(&path, b"{\"a\":2}").expect("second write");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":2}");
    }
}
