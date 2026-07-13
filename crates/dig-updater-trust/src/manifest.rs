//! The signed feed wire types: the root→targets [`Delegation`] and the update
//! [`Manifest`], each wrapped with a detached Ed25519 signature.
//!
//! ## Canonical signing bytes
//!
//! A signature is computed over the **canonical JSON** of the *payload* struct
//! ([`Delegation`] / [`Manifest`]) — its UTF-8 `serde_json` serialization. serde emits
//! struct fields in declaration order and these payloads contain no maps, so the encoding
//! is deterministic: the same payload always produces the same bytes on the signer and the
//! verifier. The detached signature and any envelope metadata are NOT part of the signed
//! bytes (a signature cannot cover itself). Signers MUST serialize the payload exactly as
//! defined here; verifiers reconstruct the same bytes via [`Delegation::signing_bytes`] /
//! [`Manifest::signing_bytes`].

use serde::{Deserialize, Serialize};

/// A root→targets delegation, signed by the pinned **root** key.
///
/// The delegation is the only thing the root key signs directly. It names the current
/// **targets** key (the online key that signs manifests), bounding the blast radius of a
/// targets-key compromise: a stolen targets key can sign manifests only until the next
/// delegation (a newer `root_version`) rotates it out, and it can never re-delegate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Monotonic delegation version. A newer delegation MUST carry a `root_version`
    /// greater than or equal to the one currently trusted; a regression is rejected.
    pub root_version: u32,
    /// Base64 (standard alphabet) of the raw 32-byte Ed25519 **targets** public key this
    /// delegation authorizes to sign manifests.
    pub targets_pubkey: String,
    /// Unix time (seconds) after which this delegation MUST NOT be trusted.
    pub expires: u64,
}

impl Delegation {
    /// The canonical bytes over which the root signature is computed (UTF-8 JSON of `self`).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Delegation is always JSON-serializable")
    }
}

/// A [`Delegation`] plus its detached root signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDelegation {
    /// The signed delegation payload.
    pub delegation: Delegation,
    /// Base64 (standard alphabet) of the 64-byte Ed25519 signature over
    /// [`Delegation::signing_bytes`], produced by the pinned **root** key.
    pub signature: String,
}

/// The update manifest: the authoritative statement of the latest build of every DIG
/// component and where to fetch it. Signed by the **targets** key named in the in-force
/// [`Delegation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest schema version. Readers accept every schema they know and MUST NOT reject
    /// a newer artifact solely for a higher schema they still understand.
    pub schema: u32,
    /// The delegation version this manifest was signed under. MUST equal the `root_version`
    /// of the [`Delegation`] whose targets key verified it (see [`verify_update_chain`]).
    ///
    /// [`verify_update_chain`]: crate::verify::verify_update_chain
    pub root_version: u32,
    /// Monotonic manifest sequence number (anti-rollback). MUST NOT regress vs the last
    /// accepted manifest.
    pub sequence: u64,
    /// Unix time (seconds) at which this manifest was generated/signed (anti-freeze
    /// high-water-mark). MUST NOT regress vs the last accepted manifest.
    pub generated: u64,
    /// Unix time (seconds) after which this manifest MUST NOT be trusted. Kept short; the
    /// feed re-signs on a heartbeat so a frozen feed expires rather than being trusted.
    pub expires: u64,
    /// The floor build number: no component build strictly below this may be installed
    /// (anti-downgrade), even if otherwise validly signed.
    pub rollback_floor_build: u64,
    /// The components this manifest describes.
    pub components: Vec<Component>,
}

impl Manifest {
    /// The canonical bytes over which the targets signature is computed (UTF-8 JSON of `self`).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Manifest is always JSON-serializable")
    }

    /// Find a component by its name.
    #[must_use]
    pub fn component(&self, name: &str) -> Option<&Component> {
        self.components.iter().find(|c| c.name == name)
    }
}

/// A [`Manifest`] plus its detached targets signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    /// The signed manifest payload.
    pub manifest: Manifest,
    /// Base64 (standard alphabet) of the 64-byte Ed25519 signature over
    /// [`Manifest::signing_bytes`], produced by the **targets** key that the in-force
    /// [`Delegation`] authorizes.
    pub signature: String,
}

/// One updatable component (e.g. `dig-node`, `dig-installer`, `dig-relay`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// The component identifier, matching the installed component's name.
    pub name: String,
    /// The human-facing semver of the latest release (e.g. `"0.26.0"`).
    pub version: String,
    /// The monotonic build number of that release, used for the anti-downgrade comparison
    /// against `rollback_floor_build` and the installed build.
    pub build: u64,
    /// The per-OS/arch downloadable artifacts for this build.
    pub artifacts: Vec<Artifact>,
}

impl Component {
    /// Find the artifact for a given OS and architecture token.
    #[must_use]
    pub fn artifact(&self, os: &str, arch: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.os == os && a.arch == arch)
    }
}

/// A single downloadable artifact for one OS/arch, with the digest that authenticates it.
///
/// The `sha256` lives inside the signed [`Manifest`], so the manifest signature is what
/// authenticates the digest; the beacon then verifies downloaded bytes against this digest
/// before install ([`verify_artifact_digest`]). The `url` is untrusted (a hostile CDN can
/// serve anything) — only the digest is trusted.
///
/// [`verify_artifact_digest`]: crate::verify::verify_artifact_digest
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// OS token (e.g. `"windows"`, `"linux"`, `"macos"`).
    pub os: String,
    /// Architecture token (e.g. `"x64"`, `"arm64"`).
    pub arch: String,
    /// The download URL. UNTRUSTED — authenticity comes from `sha256`, not from the URL/TLS.
    pub url: String,
    /// Lowercase hex (64 chars) of the SHA-256 of the artifact bytes.
    pub sha256: String,
    /// Expected size in bytes (advisory; the digest is the authority).
    pub size: u64,
}
