//! Transparency-log inputs for a signed feed (#533, alpha: log-only).
//!
//! A public transparency log (Rekor) records, for every signed manifest, the exact bytes the
//! targets key signed together with the detached signature and the signing public key. Anyone can
//! then prove — independently of DIG — that a given manifest was publicly logged, turning a silent
//! key compromise into a publicly-visible one. In alpha this is **log-only**: the CI workflow
//! uploads the entry fail-soft (a log outage never blocks the 6-hour heartbeat, SPEC §7), and the
//! beacon does NOT yet require an inclusion proof — that verification is a beta client obligation
//! (#533, deferred).
//!
//! This module produces the three files `rekor-cli` consumes, deriving them from the already-signed
//! feed so there is no second serializer to drift from the trust core:
//!
//! * [`SIGNING_BYTES_FILE`] — the manifest payload EXACTLY as served ([`SignedManifest`]'s captured
//!   received bytes, SPEC §5.4);
//! * [`SIGNATURE_FILE`] — the detached raw 64-byte Ed25519 signature over those bytes;
//! * [`TARGETS_PUBKEY_FILE`] — the targets public key as an Ed25519 SubjectPublicKeyInfo PEM.

use std::path::Path;

use base64::Engine as _;

use dig_updater_trust::{SignedDelegation, SignedManifest};

use crate::{error::FeedsignError, SignedFeed};

/// The canonical signed-payload file: the manifest bytes the targets signature covers.
pub const SIGNING_BYTES_FILE: &str = "manifest.signing-bytes";
/// The detached signature file: the raw 64-byte Ed25519 signature over [`SIGNING_BYTES_FILE`].
pub const SIGNATURE_FILE: &str = "manifest.sig";
/// The signing public key file: the targets key as an Ed25519 SubjectPublicKeyInfo PEM.
pub const TARGETS_PUBKEY_FILE: &str = "targets.pub.pem";

/// The fixed 12-byte DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410 §4):
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused bits) { <32-byte key> } }`.
/// The raw 32-byte public key follows this prefix, for 44 bytes of DER total.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The transparency-log inputs for one signed manifest: the exact signed bytes, the detached
/// signature over them, and the targets public key that produced it. Derive it from a produced
/// feed with [`SignedFeed::transparency`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparencyRecord {
    /// The manifest payload bytes the targets signature covers — the crate's canonicalization,
    /// captured verbatim (SPEC §5.4), never a re-serialization.
    pub signing_bytes: Vec<u8>,
    /// The raw 64-byte Ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: Vec<u8>,
    /// The raw 32-byte Ed25519 targets public key that produced the signature.
    pub targets_pubkey: [u8; 32],
}

impl TransparencyRecord {
    /// The targets public key as an Ed25519 SubjectPublicKeyInfo PEM (RFC 8410) — the form
    /// `rekor-cli upload --pki-format=x509 --public-key` accepts.
    #[must_use]
    pub fn targets_pubkey_pem(&self) -> String {
        let mut der = SPKI_ED25519_PREFIX.to_vec();
        der.extend_from_slice(&self.targets_pubkey);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let wrapped = b64
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----\n")
    }

    /// Write the triple into `dir` as [`SIGNING_BYTES_FILE`], [`SIGNATURE_FILE`], and
    /// [`TARGETS_PUBKEY_FILE`] — the exact inputs the workflow feeds to `rekor-cli`.
    ///
    /// # Errors
    ///
    /// [`FeedsignError::Io`] if the directory cannot be created or a file cannot be written.
    pub fn write_to(&self, dir: &Path) -> Result<(), FeedsignError> {
        std::fs::create_dir_all(dir).map_err(|e| FeedsignError::Io(e.to_string()))?;
        std::fs::write(dir.join(SIGNING_BYTES_FILE), &self.signing_bytes)
            .map_err(|e| FeedsignError::Io(e.to_string()))?;
        std::fs::write(dir.join(SIGNATURE_FILE), &self.signature)
            .map_err(|e| FeedsignError::Io(e.to_string()))?;
        std::fs::write(dir.join(TARGETS_PUBKEY_FILE), self.targets_pubkey_pem())
            .map_err(|e| FeedsignError::Io(e.to_string()))?;
        Ok(())
    }
}

impl SignedFeed {
    /// Derive the transparency record for this feed's signed **manifest** — the artifact a log
    /// entry attests. It is reconstructed entirely from the produced envelopes (reusing the trust
    /// core's parsing, so nothing here re-canonicalizes): the manifest's captured signed bytes and
    /// detached signature, and the targets public key the delegation names.
    ///
    /// # Errors
    ///
    /// [`FeedsignError::Transparency`] if a just-produced envelope cannot be re-read — which cannot
    /// happen for a feed this signer produced, but is surfaced rather than panicked.
    pub fn transparency(&self) -> Result<TransparencyRecord, FeedsignError> {
        let manifest = SignedManifest::from_json(&self.manifest_json)
            .map_err(|e| FeedsignError::Transparency(format!("re-read manifest: {e}")))?;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&manifest.signature)
            .map_err(|e| FeedsignError::Transparency(format!("decode signature: {e}")))?;

        let delegation = SignedDelegation::from_json(&self.delegation_json)
            .map_err(|e| FeedsignError::Transparency(format!("re-read delegation: {e}")))?;
        let pubkey_bytes = base64::engine::general_purpose::STANDARD
            .decode(&delegation.delegation.targets_pubkey)
            .map_err(|e| FeedsignError::Transparency(format!("decode targets pubkey: {e}")))?;
        let targets_pubkey: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
            FeedsignError::Transparency("targets pubkey is not 32 bytes".to_string())
        })?;

        Ok(TransparencyRecord {
            signing_bytes: manifest.signed_payload().to_vec(),
            signature,
            targets_pubkey,
        })
    }
}
