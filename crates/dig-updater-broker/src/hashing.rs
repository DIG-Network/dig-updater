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

/// Read an installed file's SHA-256 as lowercase hex, or `None` when there is no readable file
/// there — the evidence source for a [`VersionEvidence::ArtifactDigest`][ev] component (SPEC §9.6).
///
/// This is how the beacon learns which build of a component is installed WITHOUT executing it: the
/// answer comes from the file's own bytes measured against the signed manifest's artifact digest,
/// rather than from the binary's self-report. Injected as a [`DigestReader`] wherever it is used, so
/// planning and the health gate stay unit-testable without real files.
///
/// `None` collapses every "no digest available" case — absent, unreadable, a symlink refused by
/// [`open_no_symlink`] — into the ONE answer the planner treats as "nothing established here". That
/// is the fail-closed direction: a component whose digest cannot be read is planned as an
/// (re)install of the verified artifact, never as current, and never as something to execute.
///
/// [ev]: crate::plan::VersionEvidence::ArtifactDigest
#[must_use]
pub fn installed_digest_hex(path: &Path) -> Option<String> {
    let digest = sha256_file(path).ok()?;
    Some(hex_lower(&digest))
}

/// A digest reader: given an installed file's path, report its SHA-256 as lowercase hex, or `None`.
/// Production passes [`installed_digest_hex`]; tests pass a scripted reader so the match, mismatch
/// and absent arms are all exercised deterministically.
pub type DigestReader<'a> = dyn Fn(&Path) -> Option<String> + 'a;

/// Render `bytes` as lowercase hex — the SAME casing the signed manifest's `sha256` fields carry, so
/// a comparison against them is a plain string equality rather than a case-folding dance.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
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

    #[test]
    fn installed_digest_hex_is_the_lowercase_hex_of_the_files_sha256() {
        // The manifest carries `sha256` as lowercase hex, so the reader must produce a string that
        // compares equal to it directly. Cross-checked against the hasher rather than a transcribed
        // literal, so the two can never drift.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dig-app");
        std::fs::write(&path, b"the-installed-bytes").unwrap();
        let expected: [u8; 32] = Sha256::digest(b"the-installed-bytes").into();

        let hex = installed_digest_hex(&path).expect("a readable file has a digest");
        assert_eq!(hex, hex_lower(&expected));
        assert_eq!(hex.len(), 64, "a SHA-256 renders as 64 hex digits");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()),
            "must be LOWERCASE hex to match the manifest's own casing: {hex}"
        );
    }

    #[test]
    fn installed_digest_hex_of_an_absent_file_is_none() {
        // The fail-closed arm: no file => nothing established => the planner installs.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            installed_digest_hex(&dir.path().join("not-installed")),
            None
        );
    }

    #[test]
    fn hex_lower_pads_every_byte_to_two_digits() {
        // A byte below 0x10 must render as `0f`, not `f` — an unpadded rendering would silently
        // shorten the string and never match a manifest digest.
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }

    #[cfg(unix)]
    #[test]
    fn installed_digest_hex_of_a_symlink_is_none_not_the_targets_digest() {
        // A symlink at the install destination must not let the beacon read some OTHER file's bytes
        // and conclude the component is current. `sha256_file` refuses it, so the reader answers
        // `None` (fail-closed → reinstall) rather than the link target's digest.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::write(&real, b"bytes-outside-the-install-root").unwrap();
        let link = dir.path().join("dig-app");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(installed_digest_hex(&link), None);
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
