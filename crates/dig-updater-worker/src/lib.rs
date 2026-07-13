#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # dig-updater-worker — the unprivileged fetch/verify worker
//!
//! The worker is the **unprivileged, sandboxed** half of the beacon and the ONLY part that
//! touches the network. Given a [`WorkerRequest`] (feed sources, persisted trust state, the
//! clock, a staging directory, the target platform) and a **root verifying key**, [`run`]:
//!
//! 1. fetches the signed delegation + manifest from the feed ladder (untrusted transport),
//! 2. parses each envelope over its EXACT received bytes ([`SignedManifest::from_json`]),
//! 3. runs the SPEC §9 trust chain steps 1–5 against the root key and the trust state
//!    ([`verify_update_chain`] — signature, delegation binding, freshness, rollback floor),
//! 4. downloads each artifact for the target platform to staging with STREAMING SHA-256 and a
//!    hard size cap, verifying the bytes against the signed digest (§9 step 6),
//!
//! and returns a [`VerifiedPlan`]. It holds **no** capability to install or replace anything, so
//! a compromise of this network-facing code cannot escalate to code execution as the installing
//! identity — the worst it can do is fail closed.
//!
//! ## Key hygiene
//!
//! [`run`] is parameterized by the root key so it is exhaustively testable with throwaway keys.
//! ONLY the `dig-updater-worker` binary pins the real trusted key
//! ([`dig_updater_trust::beacon_root_verifying_key`]); no request field, environment variable, or
//! build feature can redirect the trust anchor at runtime.
//!
//! [`SignedManifest::from_json`]: dig_updater_trust::SignedManifest::from_json
//! [`verify_update_chain`]: dig_updater_trust::verify_update_chain

mod error;
mod feed;
mod net;
mod report;

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;

use dig_updater_trust::{
    verify_update_chain, Artifact, Component, SignedDelegation, SignedManifest,
};

pub use error::WorkerError;
pub use feed::{
    production_feed_ladder, FeedSource, Platform, FALLBACK_FEED_BASE, PRIMARY_FEED_BASE,
};
pub use net::{size_cap, HARD_CEILING_BYTES};
pub use report::{StagedArtifact, VerifiedPlan, WorkerReport, WorkerRequest};

/// Run one fetch → verify → stage pass against the given root key.
///
/// Returns a [`VerifiedPlan`] only if the whole trust chain verified and every platform artifact
/// matched its signed digest. Any failure — unreachable feed, bad signature, expired, replayed,
/// downgraded, oversize, digest mismatch, malformed encoding — is a [`WorkerError`] and the
/// worker installs nothing (there is no install path here regardless).
///
/// This performs no state mutation and no install: it is safe to call for a dry run.
///
/// # Errors
///
/// See [`WorkerError`] for the full taxonomy; every variant fails closed.
pub fn run(request: &WorkerRequest, root: &VerifyingKey) -> Result<VerifiedPlan, WorkerError> {
    let feed = fetch_feed(&request.feed_sources)?;

    // Parse each envelope, capturing the exact received payload bytes the signature covers.
    let delegation = SignedDelegation::from_json(&feed.delegation_json)?;
    let manifest = SignedManifest::from_json(&feed.manifest_json)?;

    // SPEC §9 steps 1–5: delegation signature + expiry, manifest signature, delegation binding,
    // freshness (anti-rollback/-freeze/-downgrade), and the rollback floor.
    verify_update_chain(
        root,
        &request.trust_state,
        &delegation,
        &manifest,
        request.now,
    )?;

    // SPEC §9 step 6: download + digest-verify each artifact for this platform, to staging.
    std::fs::create_dir_all(&request.staging_dir).map_err(|e| WorkerError::Io(e.to_string()))?;
    let staging_dir = Path::new(&request.staging_dir);
    let mut artifacts = Vec::new();
    for component in &manifest.manifest.components {
        if let Some(artifact) = component.artifact(&request.platform.os, &request.platform.arch) {
            artifacts.push(stage_artifact(staging_dir, component, artifact)?);
        }
    }

    let m = &manifest.manifest;
    Ok(VerifiedPlan {
        source: feed.source,
        schema: m.schema,
        root_version: m.root_version,
        sequence: m.sequence,
        generated: m.generated,
        rollback_floor_build: m.rollback_floor_build,
        artifacts,
    })
}

/// A verified-transport-independent bundle of the two signed feed documents plus which source
/// served them.
#[derive(Debug)]
struct FetchedFeed {
    source: String,
    delegation_json: String,
    manifest_json: String,
}

/// Try each feed source in order; the first that returns BOTH a delegation and a manifest wins.
/// Transport failures are not security events — they only mean "try the next source" and, if all
/// fail, [`WorkerError::FeedUnavailable`] (a transient, retry-next-pass outcome).
fn fetch_feed(sources: &[FeedSource]) -> Result<FetchedFeed, WorkerError> {
    let mut last_error = String::from("no feed sources configured");
    for source in sources {
        match net::fetch_text(&source.delegation_url()) {
            Ok(delegation_json) => match net::fetch_text(&source.manifest_url()) {
                Ok(manifest_json) => {
                    return Ok(FetchedFeed {
                        source: source.base.clone(),
                        delegation_json,
                        manifest_json,
                    })
                }
                Err(e) => last_error = e.to_string(),
            },
            Err(e) => last_error = e.to_string(),
        }
    }
    Err(WorkerError::FeedUnavailable(last_error))
}

/// Download one artifact to staging with a size cap + streaming digest check, returning its
/// staged record.
fn stage_artifact(
    staging_dir: &Path,
    component: &Component,
    artifact: &Artifact,
) -> Result<StagedArtifact, WorkerError> {
    let dest = staging_dir.join(staging_file_name(component, artifact));
    let written = net::download_and_verify(
        &artifact.url,
        &artifact.sha256,
        net::size_cap(artifact.size),
        &dest,
    )?;
    Ok(StagedArtifact {
        component: component.name.clone(),
        version: component.version.clone(),
        build: component.build,
        os: artifact.os.clone(),
        arch: artifact.arch.clone(),
        sha256: artifact.sha256.to_ascii_lowercase(),
        size: written,
        staged_path: dest.to_string_lossy().into_owned(),
    })
}

/// A flat, path-separator-free staging file name for an artifact. The manifest is trusted only
/// AFTER it verifies, but sanitizing the components into a single filename is defense-in-depth:
/// even a compromised targets key cannot make the (unprivileged) worker write outside staging.
fn staging_file_name(component: &Component, artifact: &Artifact) -> PathBuf {
    let name = format!(
        "{}-{}-{}-{}",
        sanitize(&component.name),
        sanitize(&component.version),
        sanitize(&artifact.os),
        sanitize(&artifact.arch),
    );
    PathBuf::from(name)
}

/// Reduce a manifest string to a safe filename segment: ASCII alphanumerics and `.`/`_`/`-` are
/// kept; everything else (path separators, control chars, …) becomes `_`.
fn sanitize(segment: &str) -> String {
    segment
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_updater_trust::Artifact;

    fn artifact() -> Artifact {
        Artifact {
            os: "linux".into(),
            arch: "x64".into(),
            url: "https://x/y".into(),
            sha256: "ab".into(),
            size: 1,
        }
    }

    #[test]
    fn staging_name_is_flat_and_separator_free() {
        let c = Component {
            name: "dig-node".into(),
            version: "0.26.0".into(),
            build: 26,
            artifacts: vec![],
        };
        let name = staging_file_name(&c, &artifact());
        assert_eq!(name.to_str().unwrap(), "dig-node-0.26.0-linux-x64");
    }

    #[test]
    fn sanitize_strips_path_separators() {
        assert_eq!(sanitize("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitize("a\\b/c"), "a_b_c");
        assert_eq!(sanitize("ok.name-1_2"), "ok.name-1_2");
    }

    #[test]
    fn malicious_component_name_cannot_escape_staging() {
        let c = Component {
            name: "../../../../tmp/evil".into(),
            version: "1".into(),
            build: 1,
            artifacts: vec![],
        };
        let name = staging_file_name(&c, &artifact());
        let s = name.to_str().unwrap();
        assert!(!s.contains('/') && !s.contains('\\'));
    }

    #[test]
    fn empty_feed_ladder_is_unavailable() {
        let err = fetch_feed(&[]).unwrap_err();
        assert!(matches!(err, WorkerError::FeedUnavailable(_)));
        assert_eq!(err.code(), "feed_unavailable");
    }
}
