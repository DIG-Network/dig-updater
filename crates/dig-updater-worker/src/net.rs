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
use std::time::Duration;

use dig_updater_trust::verify_sha256;
use sha2::{Digest, Sha256};

use crate::error::WorkerError;

/// The absolute ceiling on any single artifact download, regardless of its advisory size: 2 GiB.
pub const HARD_CEILING_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Read granularity while streaming an artifact (64 KiB).
const CHUNK_BYTES: usize = 64 * 1024;

/// Per-read stall guard: the longest a single socket read may block.
///
/// Set on every agent as a secondary bound. Note `ureq`'s overall `.timeout()` takes PRECEDENCE
/// over `.timeout_read()` for body reads, so where an overall budget is also set (both agents
/// below) the overall deadline is the effective wall-clock bound; this value still governs the
/// phases the overall deadline does not (and documents intent). Thirty seconds is far longer than
/// any healthy server's inter-packet gap.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Overall wall-clock deadline for a small feed document (delegation/manifest JSON).
///
/// These are kilobytes; a live server answers in well under a second, so a tight bound is safe. A
/// hostile CDN that sends `200 OK` then FREEZES the body (dig_ecosystem#1941) is aborted here
/// instead of blocking forever — which matters because the beacon holds the single-instance flock
/// for the whole pass, so a permanent block would wedge the update channel and every later daily
/// fire would be an `already_running` no-op. Failing CLOSED (a [`WorkerError::Fetch`]) lets the
/// flock release and the next wake retry.
const JSON_OVERALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Overall wall-clock deadline for one artifact download.
///
/// Larger than the JSON bound because an artifact can legitimately be big; sized to admit a
/// large-but-live download over an ordinary link while still failing CLOSED on a wedge. A beacon
/// pass that exceeds it aborts and the next daily fire retries, so a genuinely slow download is
/// delayed, never lost — whereas a hostile stall can never hold the channel open past this bound.
const ARTIFACT_OVERALL_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Build a timeout-bounded HTTP agent. Both a per-read timeout and an overall deadline are set so
/// no fetch can ever block indefinitely. The budgets are parameters purely so tests can drive the
/// stall paths with tiny values; production uses the constants above.
fn build_agent(read: Duration, overall: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_read(read)
        .timeout(overall)
        .build()
}

/// The production agent for a small feed document.
fn json_agent() -> ureq::Agent {
    build_agent(READ_TIMEOUT, JSON_OVERALL_TIMEOUT)
}

/// The production agent for an artifact download.
fn artifact_agent() -> ureq::Agent {
    build_agent(READ_TIMEOUT, ARTIFACT_OVERALL_TIMEOUT)
}

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
    fetch_text_with(&json_agent(), url)
}

/// [`fetch_text`], with the timeout-bounded agent injected so a stalled body can be exercised in a
/// test under a tiny budget. A stalled or frozen transport surfaces as [`WorkerError::Fetch`], so
/// the pass fails closed and retries next wake rather than blocking forever.
fn fetch_text_with(agent: &ureq::Agent, url: &str) -> Result<String, WorkerError> {
    let response = agent.get(url).call().map_err(|e| WorkerError::Fetch {
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
    download_and_verify_with(&artifact_agent(), url, expected_hex, cap, dest)
}

/// [`download_and_verify`], with the timeout-bounded agent injected so the body-stall path can be
/// driven by a test under a tiny read budget. A stalled body aborts with [`WorkerError::Fetch`]
/// (fail-closed) and the partial staging file is discarded, exactly as a transport error is.
fn download_and_verify_with(
    agent: &ureq::Agent,
    url: &str,
    expected_hex: &str,
    cap: u64,
    dest: &Path,
) -> Result<u64, WorkerError> {
    let response = agent.get(url).call().map_err(|e| WorkerError::Fetch {
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

    use std::net::TcpListener;

    /// A tiny overall budget so the stall tests finish fast. `ureq`'s overall `.timeout()` takes
    /// precedence over `.timeout_read()` for body reads, so this is the value that actually bounds a
    /// frozen transfer — exactly the wall-clock guarantee production relies on, just scaled down (the
    /// same "inject a tiny budget" idiom `probe.rs`/`loadable.rs` use).
    const TEST_OVERALL_TIMEOUT: Duration = Duration::from_secs(1);

    /// Bind a loopback listener and serve exactly one connection off a background thread using
    /// `serve`, returning the `http://127.0.0.1:PORT/` base URL. The server thread is detached; the
    /// test process exits regardless, and each test binds its own ephemeral port.
    fn serve_once(serve: impl FnOnce(std::net::TcpStream) + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let url = format!("http://{}/", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                serve(stream);
            }
        });
        url
    }

    /// Read (and discard) the request line + headers so the client's write side completes before we
    /// start (mis)behaving on the response.
    fn drain_request(stream: &std::net::TcpStream) {
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if line == "\r\n" || line.is_empty() {
                break;
            }
            line.clear();
        }
    }

    /// THE POINT (dig_ecosystem#1941): a server that sends `200 OK` + a Content-Length then FREEZES
    /// the body must not hang the artifact download forever. With the unbounded `ureq::get().call()`
    /// this replaces, the streamed read would block until the process died; the read timeout makes it
    /// fail closed instead. The assertion is only reachable because the read is bounded.
    #[test]
    fn a_frozen_artifact_body_aborts_within_the_read_timeout() {
        let url = serve_once(|mut stream| {
            drain_request(&stream);
            // Promise 1 MiB, send one byte, then never send the rest and never close.
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\nX");
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(60));
        });

        let agent = build_agent(READ_TIMEOUT, TEST_OVERALL_TIMEOUT);
        let dest = tempfile::NamedTempFile::new().expect("staging file");
        let started = std::time::Instant::now();
        let result =
            download_and_verify_with(&agent, &url, &"0".repeat(64), 10 * 1024 * 1024, dest.path());
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(WorkerError::Fetch { .. })),
            "a frozen body must fail closed with Fetch, got: {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the download returned only after {elapsed:?}; the transfer is not bounded by its budget"
        );
        // The partial staging file must not survive a failed download (verify-then-keep).
        assert!(
            !dest.path().exists()
                || std::fs::metadata(dest.path()).map(|m| m.len()).unwrap_or(0) == 0,
            "a failed download left staged bytes behind"
        );
    }

    /// The same freeze on the small-JSON path (`fetch_text`) must also fail closed, not wedge the
    /// feed fetch that every pass begins with.
    #[test]
    fn a_frozen_json_body_aborts_within_the_read_timeout() {
        let url = serve_once(|mut stream| {
            drain_request(&stream);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n{");
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(60));
        });

        let agent = build_agent(READ_TIMEOUT, TEST_OVERALL_TIMEOUT);
        let started = std::time::Instant::now();
        let result = fetch_text_with(&agent, &url);
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(WorkerError::Fetch { .. })),
            "a frozen JSON body must fail closed with Fetch, got: {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "fetch_text returned only after {elapsed:?}; the transfer is not bounded by its budget"
        );
    }
}
