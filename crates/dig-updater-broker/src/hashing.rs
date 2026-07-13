//! The broker's file-hashing primitives — a **symlink-safe** open and a standalone streaming
//! SHA-256.
//!
//! The broker never trusts the digest the worker reported (SPEC §8.3). On the install path it
//! copies the staged bytes into a broker-private file while hashing them in one read (see
//! [`crate::install::stage_and_verify_private`]); on the rollback path it re-hashes a cached binary
//! with [`sha256_file`] before reinstating it. Both compare against the digest carried in the
//! RE-VERIFIED manifest / the snapshot record.
//!
//! [`open_no_symlink`] refuses to follow a symlink at the final path component. A staged file that
//! is a symlink is treated as tampering: an attacker who could plant a symlink in the staging
//! directory could otherwise redirect the broker's read (and the subsequent copy) to bytes outside
//! it. Combined with a broker-owned, non-world-writable staging directory, this closes the
//! symlink-swap vector on the install path.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::BrokerError;

/// Read granularity while hashing a (possibly large) staged artifact.
const CHUNK_BYTES: usize = 64 * 1024;

/// Open `path` for reading, REFUSING to follow a symlink at the final component.
///
/// # Errors
///
/// [`BrokerError::Io`] if the path is a symlink, is missing, or cannot be opened.
pub fn open_no_symlink(path: &Path) -> Result<File, BrokerError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| BrokerError::Io(e.to_string()))?;
    if meta.file_type().is_symlink() {
        return Err(BrokerError::Io(format!(
            "refusing to open symlink `{}` on the install path",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        // O_NOFOLLOW closes the metadata→open race: even if the entry were swapped for a symlink
        // between the check above and this open, the open itself fails.
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| BrokerError::Io(e.to_string()))
    }
    #[cfg(not(unix))]
    {
        File::open(path).map_err(|e| BrokerError::Io(e.to_string()))
    }
}

/// Stream-hash the file at `path` (symlink-safe) into its SHA-256, without loading it whole into
/// memory.
///
/// # Errors
///
/// [`BrokerError::Io`] if the file is a symlink, is missing, or cannot be read.
pub fn sha256_file(path: &Path) -> Result<[u8; 32], BrokerError> {
    let mut file = open_no_symlink(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_BYTES];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| BrokerError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_file_matches_a_known_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bytes");
        std::fs::write(&path, b"the-artifact-bytes").unwrap();
        // Known SHA-256 of "the-artifact-bytes", cross-checked against the trust core's hasher.
        let expected: [u8; 32] = Sha256::digest(b"the-artifact-bytes").into();
        assert_eq!(sha256_file(&path).unwrap(), expected);
    }

    #[test]
    fn missing_file_is_an_io_error() {
        let missing = std::env::temp_dir().join("dig-updater-hashing-definitely-missing");
        assert!(matches!(sha256_file(&missing), Err(BrokerError::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_hash_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"secret-outside-staging").unwrap();
        let link = dir.path().join("staged");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = sha256_file(&link).expect_err("a symlinked staged file must be refused");
        assert!(err.to_string().contains("symlink"));
    }
}
