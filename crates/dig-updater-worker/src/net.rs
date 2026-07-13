//! The network edge: fetch small signed JSON documents, and stream a (potentially large,
//! potentially hostile) artifact to staging while hashing it and enforcing a hard size cap.
//!
//! Nothing here is trusted. The JSON is only trusted once its signature verifies (the caller's
//! job); an artifact's bytes are only trusted once [`download_and_verify`] confirms their
//! SHA-256 equals the digest carried in the signed manifest. The size cap exists purely to stop
//! a hostile CDN from filling the disk *before* the digest can reject the bytes.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use dig_updater_trust::verify_sha256;
use sha2::{Digest, Sha256};

use crate::error::WorkerError;

/// The absolute ceiling on any single artifact download, regardless of its advisory size: 2 GiB.
pub const HARD_CEILING_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Read granularity while streaming an artifact (64 KiB).
const CHUNK_BYTES: usize = 64 * 1024;

/// The per-artifact download cap: `min(4 × advisory_size, 2 GiB)`.
///
/// The 4× headroom tolerates an honest advisory that undercounts (compression, packaging) while
/// still bounding a hostile stream; the 2 GiB ceiling bounds even an artifact with an absurd
/// advisory. `saturating_mul` avoids overflow on a maliciously huge advisory.
#[must_use]
pub fn size_cap(advisory_size: u64) -> u64 {
    advisory_size.saturating_mul(4).min(HARD_CEILING_BYTES)
}

/// Fetch a small JSON document (a delegation or manifest) as text.
///
/// # Errors
///
/// [`WorkerError::Fetch`] on any transport error or non-2xx status.
pub fn fetch_text(url: &str) -> Result<String, WorkerError> {
    let response = ureq::get(url).call().map_err(|e| WorkerError::Fetch {
        url: url.to_string(),
        detail: e.to_string(),
    })?;
    response.into_string().map_err(|e| WorkerError::Fetch {
        url: url.to_string(),
        detail: e.to_string(),
    })
}

/// Stream the artifact at `url` into `dest`, hashing as it arrives, refusing to accept more than
/// `cap` bytes, then verifying the SHA-256 against `expected_hex`. Returns the number of bytes
/// written on success.
///
/// On ANY failure — oversize, transport error, or digest mismatch — the partially-written
/// staging file is removed so no unverified bytes are ever left where the broker could install
/// them. This is **verify-then-keep**: only a digest-verified file survives.
///
/// # Errors
///
/// - [`WorkerError::ArtifactTooLarge`] if the stream exceeds `cap`.
/// - [`WorkerError::Fetch`] on a transport error.
/// - [`WorkerError::Io`] on a staging write/create error.
/// - [`WorkerError::Trust`] ([`TrustError::DigestMismatch`]/[`TrustError::BadDigestHex`]) if the
///   verified bytes do not match the signed digest.
///
/// [`TrustError::DigestMismatch`]: dig_updater_trust::TrustError::DigestMismatch
/// [`TrustError::BadDigestHex`]: dig_updater_trust::TrustError::BadDigestHex
pub fn download_and_verify(
    url: &str,
    expected_hex: &str,
    cap: u64,
    dest: &Path,
) -> Result<u64, WorkerError> {
    let response = ureq::get(url).call().map_err(|e| WorkerError::Fetch {
        url: url.to_string(),
        detail: e.to_string(),
    })?;
    let mut reader = response.into_reader();
    let mut file = File::create(dest).map_err(|e| WorkerError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut total: u64 = 0;

    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                discard(file, dest);
                return Err(WorkerError::Fetch {
                    url: url.to_string(),
                    detail: e.to_string(),
                });
            }
        };
        total = total.saturating_add(n as u64);
        if total > cap {
            // Reject BEFORE writing the overflowing chunk — never let the disk fill.
            discard(file, dest);
            return Err(WorkerError::ArtifactTooLarge {
                url: url.to_string(),
                limit: cap,
            });
        }
        hasher.update(&buf[..n]);
        if let Err(e) = file.write_all(&buf[..n]) {
            discard(file, dest);
            return Err(WorkerError::Io(e.to_string()));
        }
    }

    // Close the handle before verifying/cleanup (Windows won't remove an open file).
    drop(file);
    let digest: [u8; 32] = hasher.finalize().into();
    if let Err(e) = verify_sha256(expected_hex, &digest) {
        let _ = std::fs::remove_file(dest);
        return Err(WorkerError::Trust(e));
    }
    Ok(total)
}

/// Close and delete a partially-written staging file, ignoring cleanup errors.
fn discard(file: File, dest: &Path) {
    drop(file);
    let _ = std::fs::remove_file(dest);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_cap_is_four_x_advisory_under_the_ceiling() {
        assert_eq!(size_cap(100), 400);
        assert_eq!(size_cap(0), 0);
    }

    #[test]
    fn size_cap_clamps_to_the_ceiling() {
        assert_eq!(size_cap(HARD_CEILING_BYTES), HARD_CEILING_BYTES);
        assert_eq!(size_cap(u64::MAX), HARD_CEILING_BYTES); // saturating, no overflow
    }
}
