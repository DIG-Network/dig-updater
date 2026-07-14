#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # dig-updater-feedsign — the CI feed signer
//!
//! This crate assembles and signs the DIG auto-update beacon's **signed feed** — the
//! `delegation.json` + `manifest.json` pair the beacon fetches, verifies, and acts on. It runs
//! ONLY in CI (a scheduled + on-demand workflow) and is NEVER packaged into the shipped beacon
//! binary; it lives in the workspace so the same gates (fmt, clippy, tests, coverage) hold it.
//!
//! ## One pass, per channel
//!
//! The beacon publishes TWO fully independent signed feeds — a [`Channel::Stable`] feed and a
//! [`Channel::Nightly`] feed — at distinct paths (`/v1/stable/`, `/v1/nightly/`), each with its own
//! freshness + anti-rollback marks but signed under the same key (SPEC §10.1). [`produce_feed`]
//! signs ONE channel; the workflow calls it once per channel. For the given channel it:
//!
//! 1. for each configured component, resolve the channel's GitHub release — `releases/latest` for
//!    stable, the rolling `releases/tags/nightly` for nightly — and pick the per-OS/arch binary
//!    assets ([`resolve`]). Stable takes the version from the release tag; nightly recovers it from
//!    the asset names (the `nightly` tag carries none, #590);
//! 2. download each asset and compute its SHA-256 (the digest that will authenticate the bytes);
//! 3. assemble the [`Manifest`] and root→targets [`Delegation`] from those builds, the per-channel
//!    anti-rollback floor, and the run's `generated` timestamp ([`assemble`]);
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
mod channel;
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
pub use channel::Channel;
pub use config::{AssetKind, ChannelFloors, ComponentConfig, FeedConfig};
pub use error::FeedsignError;
pub use resolve::{resolve_version_from_assets, select_artifacts, GithubRelease, ResolvedArtifact};
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

/// Assemble and sign one `channel`'s feed for one run (SPEC §10.1).
///
/// The `signing_key` is used for BOTH the root delegation signature and the targets manifest
/// signature (alpha floor: root == targets, SPEC §4.3), and the SAME key signs every channel. The
/// caller is responsible for having confirmed the key is the pinned root ([`assert_pinned_root`]) —
/// the CI binary does so before calling this; tests pass a throwaway key deliberately.
///
/// The channel changes only which release supplies each component's build, how its `build` number
/// is scaled, and which anti-rollback floor applies (see [`Channel`]); everything else is shared.
///
/// # Errors
///
/// [`FeedsignError`] if any component cannot be resolved, an asset cannot be downloaded, or a
/// version cannot be parsed. Fails closed: a partial resolution never yields a feed.
pub fn produce_feed(
    config: &FeedConfig,
    source: &dyn ReleaseSource,
    channel: Channel,
    generated: u64,
    signing_key: &SigningKey,
) -> Result<SignedFeed, FeedsignError> {
    let mut components = Vec::with_capacity(config.components.len());
    let mut digests = Vec::new();

    for component in &config.components {
        let release = source.release(&component.repo, channel)?;
        let (version_str, build) = resolve_version(&release, component, channel)?;
        let resolved = select_artifacts(&release, component, &version_str)?;

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
            build,
            artifacts,
        });
    }

    let manifest = assemble_manifest(config, config.floor_for(channel), generated, components);
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

/// Resolve a component's `(version_string, build_number)` for `channel` from its `release`.
///
/// The two channels differ only here (SPEC §10.1, #591 D2):
///
/// - **stable** — the version is the release tag with any leading `v` stripped (`v0.29.0` →
///   `0.29.0`), and the `build` is the packed monotonic semver (`major·10⁶ + minor·10³ + patch`);
/// - **nightly** — the tag is the literal `nightly`, so the version (`X.Y.Z-nightly.YYYYMMDD.<sha>`)
///   is recovered from the asset names, and the `build` is the UTC build date `YYYYMMDD`. The FULL
///   prerelease string is kept as the manifest `version` so the beacon's enumerate/plan compares
///   against the real installed nightly version, not a stripped semver (#591 D5 point 5).
fn resolve_version(
    release: &GithubRelease,
    component: &ComponentConfig,
    channel: Channel,
) -> Result<(String, u64), FeedsignError> {
    match channel {
        Channel::Stable => {
            let version_str = release.asset_version().to_string();
            let build = version::parse_version(&release.tag_name)?.build_number();
            Ok((version_str, build))
        }
        Channel::Nightly => {
            let version_str = resolve_version_from_assets(release, component)?;
            let build = version::parse_nightly_build(&version_str)?;
            Ok((version_str, build))
        }
    }
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
