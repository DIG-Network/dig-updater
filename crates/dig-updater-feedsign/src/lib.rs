#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # dig-updater-feedsign — the CI feed signer
//!
//! This crate assembles and signs the DIG auto-update beacon's **signed feed** — the
//! `delegation.json` + `manifest.json` pair the beacon fetches, verifies, and acts on. It runs
//! ONLY in CI (a scheduled + on-demand workflow) and is NEVER packaged into the shipped beacon
//! binary; it lives in the workspace so the same gates (fmt, clippy, tests, coverage) hold it.
//!
//! ## One pass
//!
//! [`produce_feed`] does the whole job:
//!
//! 1. for each configured component, resolve its latest GitHub release and pick the per-OS/arch
//!    binary assets ([`resolve`]);
//! 2. download each asset and compute its SHA-256 (the digest that will authenticate the bytes);
//! 3. assemble the [`Manifest`] and root→targets [`Delegation`] from those builds plus the run's
//!    `generated` timestamp ([`assemble`]);
//! 4. **sign** both with the beacon trust core's own signer — [`SignedManifest::sign`] /
//!    [`SignedDelegation::sign`] — and serialize them byte-exactly with `.to_json()`.
//!
//! ## Signer/verifier can never drift
//!
//! Signing goes through [`dig_updater_trust`], the SAME crate the beacon verifies with. The
//! signature covers the payload's canonical bytes ([`Manifest::signing_bytes`]) and the emitted
//! envelope embeds those exact bytes verbatim, so a beacon verifying over the received slice
//! (SPEC §5.4) accepts them. There is no second, independent serializer to fall out of sync.
//!
//! ## Determinism
//!
//! Nothing here reads the clock: the `generated` timestamp is passed in (the workflow supplies
//! it). Given the same inputs the output is byte-identical — which is what lets the feed be served
//! byte-for-byte as signed (SPEC §10, the no-transform requirement).

mod assemble;
mod config;
mod error;
mod resolve;
mod sign;
mod source;
mod transparency;
mod version;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use dig_updater_trust::{Artifact, Component, SignedDelegation, SignedManifest};

pub use assemble::{assemble_delegation, assemble_manifest};
pub use config::{ComponentConfig, FeedConfig};
pub use error::FeedsignError;
pub use resolve::{select_artifacts, GithubRelease, ResolvedArtifact};
pub use sign::{assert_pinned_root, is_pinned_root, signing_key_from_secret};
pub use source::{GithubSource, ReleaseSource};
pub use transparency::{
    TransparencyRecord, SIGNATURE_FILE, SIGNING_BYTES_FILE, TARGETS_PUBKEY_FILE,
};

/// The names of the two feed objects, at `{feed-base}/{delegation,manifest}.json` (SPEC §10).
pub const DELEGATION_FILE: &str = "delegation.json";
/// The manifest file name served alongside the delegation.
pub const MANIFEST_FILE: &str = "manifest.json";

/// A produced, signed feed: the two byte-exact JSON documents plus a summary of what was signed
/// (safe, non-secret metadata for the CI job summary — sequence, timestamp, and per-artifact
/// digests).
#[derive(Debug, Clone)]
pub struct SignedFeed {
    /// The signed `delegation.json`, byte-exact.
    pub delegation_json: String,
    /// The signed `manifest.json`, byte-exact.
    pub manifest_json: String,
    /// The manifest `sequence` (== `generated`).
    pub sequence: u64,
    /// The manifest `generated` timestamp.
    pub generated: u64,
    /// One entry per signed artifact — for the job summary. Digests are public, not secret.
    pub digests: Vec<ArtifactDigest>,
}

/// A non-secret record of one signed artifact, for the CI job summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDigest {
    /// The component this artifact belongs to.
    pub component: String,
    /// The component's resolved version.
    pub version: String,
    /// The artifact's OS token.
    pub os: String,
    /// The artifact's arch token.
    pub arch: String,
    /// The artifact's lowercase-hex SHA-256.
    pub sha256: String,
    /// The artifact's byte size.
    pub size: u64,
}

/// Standard-alphabet base64 of the raw key bytes.
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Assemble and sign the feed for one run.
///
/// The `signing_key` is used for BOTH the root delegation signature and the targets manifest
/// signature (alpha floor: root == targets, SPEC §4.3). The caller is responsible for having
/// confirmed the key is the pinned root ([`assert_pinned_root`]) — the CI binary does so before
/// calling this; tests pass a throwaway key deliberately.
///
/// # Errors
///
/// [`FeedsignError`] if any component cannot be resolved, an asset cannot be downloaded, or a
/// version tag cannot be parsed. Fails closed: a partial resolution never yields a feed.
pub fn produce_feed(
    config: &FeedConfig,
    source: &dyn ReleaseSource,
    generated: u64,
    signing_key: &SigningKey,
) -> Result<SignedFeed, FeedsignError> {
    let mut components = Vec::with_capacity(config.components.len());
    let mut digests = Vec::new();

    for component in &config.components {
        let release = source.latest_release(&component.repo)?;
        let version = version::parse_version(&release.tag_name)?;
        let version_str = release.asset_version().to_string();
        let resolved = select_artifacts(&release, component)?;

        let mut artifacts = Vec::with_capacity(resolved.len());
        for artifact in resolved {
            let bytes = source.download(&artifact.url)?;
            let sha256 = hex::encode(Sha256::digest(&bytes));
            let size = bytes.len() as u64;
            digests.push(ArtifactDigest {
                component: component.name.clone(),
                version: version_str.clone(),
                os: artifact.os.clone(),
                arch: artifact.arch.clone(),
                sha256: sha256.clone(),
                size,
            });
            artifacts.push(Artifact {
                os: artifact.os,
                arch: artifact.arch,
                url: artifact.url,
                sha256,
                size,
            });
        }

        components.push(Component {
            name: component.name.clone(),
            version: version_str,
            build: version.build_number(),
            artifacts,
        });
    }

    let manifest = assemble_manifest(config, generated, components);
    let targets_pubkey = b64(&signing_key.verifying_key().to_bytes());
    let delegation = assemble_delegation(config, generated, targets_pubkey);

    Ok(SignedFeed {
        delegation_json: SignedDelegation::sign(delegation, signing_key).to_json(),
        manifest_json: SignedManifest::sign(manifest, signing_key).to_json(),
        sequence: generated,
        generated,
        digests,
    })
}

impl SignedFeed {
    /// Write the two feed objects into `dir` as `delegation.json` + `manifest.json`.
    ///
    /// # Errors
    ///
    /// [`FeedsignError::Io`] if the directory cannot be created or a file cannot be written.
    pub fn write_to(&self, dir: &std::path::Path) -> Result<(), FeedsignError> {
        std::fs::create_dir_all(dir).map_err(|e| FeedsignError::Io(e.to_string()))?;
        std::fs::write(dir.join(DELEGATION_FILE), &self.delegation_json)
            .map_err(|e| FeedsignError::Io(e.to_string()))?;
        std::fs::write(dir.join(MANIFEST_FILE), &self.manifest_json)
            .map_err(|e| FeedsignError::Io(e.to_string()))?;
        Ok(())
    }

    /// A secret-free, human + machine readable summary of what was signed, for the CI job
    /// summary. It prints ONLY the sequence, timestamp, and per-artifact digests — never the key.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = format!(
            "signed feed: sequence={} generated={} artifacts={}",
            self.sequence,
            self.generated,
            self.digests.len()
        );
        for d in &self.digests {
            out.push_str(&format!(
                "\n  {} {} [{}-{}] {} ({} bytes)",
                d.component, d.version, d.os, d.arch, d.sha256, d.size
            ));
        }
        out
    }
}
