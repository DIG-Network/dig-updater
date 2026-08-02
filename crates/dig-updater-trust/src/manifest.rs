//! The signed feed wire types: the root→targets [`Delegation`] and the update
//! [`Manifest`], each wrapped with a detached Ed25519 signature.
//!
//! ## Verification is over the RECEIVED bytes, not a re-serialization (forward-compat)
//!
//! A signature covers the exact UTF-8 JSON bytes of the *payload* object as they appear on the
//! wire. A verifier MUST check the signature over **those received bytes** — captured verbatim
//! via [`serde_json::value::RawValue`] in [`SignedDelegation::from_json`] /
//! [`SignedManifest::from_json`] — and MUST NOT re-serialize the parsed struct and verify over
//! that. Re-serializing would silently drop any field the reader's struct does not know, so a
//! future feed that adds an (additive, backward-compatible) field would fail to verify under an
//! older beacon — breaking the SPEC §5.2 forward-compatibility guarantee. Capturing the raw
//! slice keeps every unknown byte inside the signed message, so the signature still verifies and
//! the reader simply ignores fields it does not understand.
//!
//! [`Delegation::signing_bytes`] / [`Manifest::signing_bytes`] therefore exist ONLY for the
//! **signer** (the CI feed-signer and tests): they define the canonical serialization a signer
//! emits. Verifiers never call them.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::verify::TrustError;

/// Standard-alphabet base64 (RFC 4648 §4), the encoding for keys and signatures on the wire.
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

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
    /// The canonical bytes a **signer** produces for this payload (UTF-8 JSON of `self`).
    ///
    /// This is the SIGNER's canonicalization only. Verifiers do NOT use it — they verify over
    /// the exact received bytes captured by [`SignedDelegation::from_json`] (see the module
    /// docs). serde emits struct fields in declaration order and this payload contains no maps,
    /// so the encoding is deterministic.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Delegation is always JSON-serializable")
    }
}

/// A [`Delegation`] plus its detached root signature and the exact payload bytes that signature
/// covers.
///
/// Construct it as a **verifier** with [`from_json`](Self::from_json) (captures the received
/// bytes) or as a **signer**/test with [`sign`](Self::sign). Verification runs over
/// [`signed_payload`](Self::signed_payload), never over a re-serialization of `delegation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDelegation {
    /// The parsed delegation payload. Convenient typed access; NOT the source of truth for the
    /// verified bytes (that is [`signed_payload`](Self::signed_payload)).
    pub delegation: Delegation,
    /// Base64 (standard alphabet) of the 64-byte Ed25519 signature over the payload bytes,
    /// produced by the pinned **root** key.
    pub signature: String,
    /// The exact payload byte slice the signature is verified over — the bytes as received on
    /// the wire (which preserves fields this reader may not understand).
    signed_payload: Vec<u8>,
}

/// The `delegation` envelope as it appears on the wire, borrowing the payload as raw bytes.
#[derive(Deserialize)]
struct DelegationEnvelope<'a> {
    #[serde(borrow)]
    delegation: &'a RawValue,
    signature: String,
}

/// The `delegation` envelope for output, embedding the exact signed payload verbatim.
#[derive(Serialize)]
struct DelegationEnvelopeOut<'a> {
    delegation: &'a RawValue,
    signature: &'a str,
}

impl SignedDelegation {
    /// Sign a delegation with the **root** signing key (the SIGNER path — CI feed-signer and
    /// tests). Captures the canonical payload bytes as the signed bytes so a subsequent
    /// [`to_json`](Self::to_json)/[`from_json`](Self::from_json) round-trip is stable.
    #[must_use]
    pub fn sign(delegation: Delegation, root: &SigningKey) -> Self {
        let signed_payload = delegation.signing_bytes();
        let signature = b64(&root.sign(&signed_payload).to_bytes());
        Self {
            delegation,
            signature,
            signed_payload,
        }
    }

    /// Parse a signed delegation from its JSON envelope, capturing the payload's EXACT received
    /// byte slice so the signature is later verified over precisely those bytes (§5.4).
    ///
    /// # Errors
    ///
    /// [`TrustError::MalformedJson`] if the envelope or its payload is not well-formed JSON.
    pub fn from_json(json: &str) -> Result<Self, TrustError> {
        let env: DelegationEnvelope =
            serde_json::from_str(json).map_err(|e| TrustError::MalformedJson(e.to_string()))?;
        let signed_payload = env.delegation.get().as_bytes().to_vec();
        let delegation: Delegation = serde_json::from_str(env.delegation.get())
            .map_err(|e| TrustError::MalformedJson(e.to_string()))?;
        Ok(Self {
            delegation,
            signature: env.signature,
            signed_payload,
        })
    }

    /// The exact payload bytes the root signature is verified over.
    #[must_use]
    pub fn signed_payload(&self) -> &[u8] {
        &self.signed_payload
    }

    /// Serialize back to the JSON envelope, embedding the exact signed payload bytes verbatim
    /// (a stable round-trip with [`from_json`](Self::from_json)).
    #[must_use]
    pub fn to_json(&self) -> String {
        let payload = RawValue::from_string(
            String::from_utf8(self.signed_payload.clone()).expect("signed payload is UTF-8 JSON"),
        )
        .expect("signed payload is valid JSON");
        serde_json::to_string(&DelegationEnvelopeOut {
            delegation: &payload,
            signature: &self.signature,
        })
        .expect("envelope is always serializable")
    }
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
    /// The canonical bytes a **signer** produces for this payload (UTF-8 JSON of `self`).
    ///
    /// SIGNER canonicalization only — verifiers verify over the received bytes captured by
    /// [`SignedManifest::from_json`] (see the module docs).
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

/// A [`Manifest`] plus its detached targets signature and the exact payload bytes that
/// signature covers.
///
/// As with [`SignedDelegation`], verification runs over [`signed_payload`](Self::signed_payload)
/// — the received bytes — so an additive future manifest field verifies under an older reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedManifest {
    /// The parsed manifest payload (typed access; NOT the verified-bytes source of truth).
    pub manifest: Manifest,
    /// Base64 (standard alphabet) of the 64-byte Ed25519 signature over the payload bytes,
    /// produced by the **targets** key the in-force [`Delegation`] authorizes.
    pub signature: String,
    /// The exact payload byte slice the signature is verified over.
    signed_payload: Vec<u8>,
}

/// The `manifest` envelope as it appears on the wire, borrowing the payload as raw bytes.
#[derive(Deserialize)]
struct ManifestEnvelope<'a> {
    #[serde(borrow)]
    manifest: &'a RawValue,
    signature: String,
}

/// The `manifest` envelope for output, embedding the exact signed payload verbatim.
#[derive(Serialize)]
struct ManifestEnvelopeOut<'a> {
    manifest: &'a RawValue,
    signature: &'a str,
}

impl SignedManifest {
    /// Sign a manifest with the **targets** signing key (SIGNER path — CI feed-signer and
    /// tests), capturing the canonical payload bytes as the signed bytes.
    #[must_use]
    pub fn sign(manifest: Manifest, targets: &SigningKey) -> Self {
        let signed_payload = manifest.signing_bytes();
        let signature = b64(&targets.sign(&signed_payload).to_bytes());
        Self {
            manifest,
            signature,
            signed_payload,
        }
    }

    /// Parse a signed manifest from its JSON envelope, capturing the payload's EXACT received
    /// byte slice so verification runs over precisely those bytes (§5.4, forward-compatible).
    ///
    /// # Errors
    ///
    /// [`TrustError::MalformedJson`] if the envelope or its payload is not well-formed JSON.
    pub fn from_json(json: &str) -> Result<Self, TrustError> {
        let env: ManifestEnvelope =
            serde_json::from_str(json).map_err(|e| TrustError::MalformedJson(e.to_string()))?;
        let signed_payload = env.manifest.get().as_bytes().to_vec();
        let manifest: Manifest = serde_json::from_str(env.manifest.get())
            .map_err(|e| TrustError::MalformedJson(e.to_string()))?;
        Ok(Self {
            manifest,
            signature: env.signature,
            signed_payload,
        })
    }

    /// The exact payload bytes the targets signature is verified over.
    #[must_use]
    pub fn signed_payload(&self) -> &[u8] {
        &self.signed_payload
    }

    /// Serialize back to the JSON envelope, embedding the exact signed payload bytes verbatim.
    #[must_use]
    pub fn to_json(&self) -> String {
        let payload = RawValue::from_string(
            String::from_utf8(self.signed_payload.clone()).expect("signed payload is UTF-8 JSON"),
        )
        .expect("signed payload is valid JSON");
        serde_json::to_string(&ManifestEnvelopeOut {
            manifest: &payload,
            signature: &self.signature,
        })
        .expect("envelope is always serializable")
    }
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
    /// Find the FIRST artifact for a given OS and architecture token.
    ///
    /// Back-compatible: where a platform ships a single build (every component but a
    /// headless-capable dig-app), this is the only artifact. Where it ships several variants
    /// (dig_ecosystem#1912), this returns the default one, because the feed lists the default
    /// (`variant == None`) first — so a caller that predates variants keeps selecting the default
    /// build unchanged. Callers that must choose among variants use [`Self::artifacts_for`].
    #[must_use]
    pub fn artifact(&self, os: &str, arch: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.os == os && a.arch == arch)
    }

    /// Every artifact for a given OS and architecture token — one per build [`Artifact::variant`]
    /// (dig_ecosystem#1912), in the order the manifest lists them (the feed-signer emits the default
    /// variant first, so a consumer that prefers the default simply takes the first).
    ///
    /// For a component that ships a single build this yields exactly one artifact — the same one
    /// [`Self::artifact`] returns — so the multi-variant path is a strict superset of the old one.
    pub fn artifacts_for<'a>(
        &'a self,
        os: &'a str,
        arch: &'a str,
    ) -> impl Iterator<Item = &'a Artifact> + 'a {
        self.artifacts
            .iter()
            .filter(move |a| a.os == os && a.arch == arch)
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
    /// Expected size in bytes (advisory; the digest is the authority). Also bounds the
    /// download: the worker refuses to stream more than `min(4 × size, 2 GiB)` (disk-fill DoS
    /// guard).
    pub size: u64,
    /// The build VARIANT within one `(os, arch)`, when a platform ships more than one build of a
    /// component that differ in what the host must be able to LOAD (dig_ecosystem#1912). The DEFAULT
    /// build carries no variant (`None`) — the desktop/tray dig-app, and every single-build
    /// component; an ALTERNATIVE build a host may need instead carries a token such as `"headless"`
    /// (the headless Linux dig-app, which does not link GTK). The beacon selects among the variants
    /// staged for its `(os, arch)` by loadability (`dig-updater-broker`'s ELF check), preferring the
    /// default.
    ///
    /// Additive + backward-compatible (SPEC §5.1/§5.2): a pre-#1912 manifest has no `variant` key on
    /// any artifact, which `#[serde(default)]` reads as `None`; `skip_serializing_if` omits the key
    /// for the default variant, so a single-variant manifest serializes BYTE-IDENTICALLY to what a
    /// pre-#1912 signer emitted, and its signature is unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    fn targets_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn sample_manifest() -> Manifest {
        Manifest {
            schema: 1,
            root_version: 1,
            sequence: 10,
            generated: 1000,
            expires: 2000,
            rollback_floor_build: 5,
            components: vec![Component {
                name: "dig-node".to_string(),
                version: "0.26.0".to_string(),
                build: 26,
                artifacts: vec![Artifact {
                    os: "linux".to_string(),
                    arch: "x64".to_string(),
                    url: "https://updates.dig.net/dig-node/0.26.0/linux-x64".to_string(),
                    sha256: hex::encode(Sha256::digest(b"artifact")),
                    size: 8,
                    variant: None,
                }],
            }],
        }
    }

    /// `from_json` after `to_json` preserves the parsed payload and the exact signed bytes.
    #[test]
    fn manifest_json_round_trip_preserves_signed_bytes() {
        let signed = SignedManifest::sign(sample_manifest(), &targets_key());
        let json = signed.to_json();
        let parsed = SignedManifest::from_json(&json).expect("valid envelope");
        assert_eq!(parsed.manifest, signed.manifest);
        assert_eq!(parsed.signed_payload(), signed.signed_payload());
        assert_eq!(parsed.signature, signed.signature);
    }

    /// The delegation envelope round-trips identically.
    #[test]
    fn delegation_json_round_trip() {
        let root = SigningKey::from_bytes(&[7u8; 32]);
        let signed = SignedDelegation::sign(
            Delegation {
                root_version: 3,
                targets_pubkey: b64(&targets_key().verifying_key().to_bytes()),
                expires: 5000,
            },
            &root,
        );
        let parsed = SignedDelegation::from_json(&signed.to_json()).expect("valid envelope");
        assert_eq!(parsed.delegation, signed.delegation);
        assert_eq!(parsed.signed_payload(), signed.signed_payload());
    }

    /// The signed bytes captured from the wire equal the raw payload substring — NOT a
    /// re-serialization. This is the property the forward-compat fix depends on.
    #[test]
    fn from_json_captures_raw_payload_verbatim() {
        // A manifest payload carrying an unknown, additive field a future feed might emit.
        let payload = r#"{"schema":2,"root_version":1,"sequence":11,"generated":1000,"expires":2000,"rollback_floor_build":5,"components":[],"future_flag":true}"#;
        let sig = "AA"; // signature content is irrelevant to byte capture
        let envelope = format!(r#"{{"manifest":{payload},"signature":"{sig}"}}"#);
        let parsed = SignedManifest::from_json(&envelope).expect("well-formed JSON");
        // The captured bytes include the unknown field verbatim...
        assert_eq!(parsed.signed_payload(), payload.as_bytes());
        // ...even though the parsed struct silently ignores it.
        assert_eq!(parsed.manifest.schema, 2);
        assert!(parsed.manifest.components.is_empty());
    }

    /// Malformed envelopes fail closed as `MalformedJson`, never a panic.
    #[test]
    fn malformed_envelope_is_rejected() {
        assert!(matches!(
            SignedManifest::from_json("not json"),
            Err(TrustError::MalformedJson(_))
        ));
        assert!(matches!(
            SignedManifest::from_json(r#"{"manifest":123,"signature":"x"}"#),
            Err(TrustError::MalformedJson(_))
        ));
        assert!(matches!(
            SignedDelegation::from_json(r#"{"signature":"x"}"#),
            Err(TrustError::MalformedJson(_))
        ));
    }

    /// Component/artifact lookups resolve as expected.
    #[test]
    fn lookups_resolve() {
        let m = sample_manifest();
        assert!(m.component("dig-node").is_some());
        assert!(m.component("nope").is_none());
        let c = m.component("dig-node").unwrap();
        assert!(c.artifact("linux", "x64").is_some());
        assert!(c.artifact("windows", "x64").is_none());
    }

    /// A second linux/x64 artifact, carrying the `headless` variant token, for the multi-variant
    /// tests — the exact shape the feed serves for dig-app under dig_ecosystem#1912.
    fn headless_variant() -> Artifact {
        Artifact {
            os: "linux".to_string(),
            arch: "x64".to_string(),
            url: "https://updates.dig.net/dig-app/3.5.0/linux-x64-headless".to_string(),
            sha256: hex::encode(Sha256::digest(b"headless-artifact")),
            size: 17,
            variant: Some("headless".to_string()),
        }
    }

    /// `artifacts_for` returns EVERY variant of a platform (default first), while `artifact` keeps
    /// returning just the default — so the multi-variant path is a strict superset of the old lookup.
    #[test]
    fn artifacts_for_returns_every_variant_default_first() {
        let mut m = sample_manifest();
        m.components[0].artifacts.push(headless_variant());
        let c = &m.components[0];

        let variants: Vec<Option<&str>> = c
            .artifacts_for("linux", "x64")
            .map(|a| a.variant.as_deref())
            .collect();
        assert_eq!(
            variants,
            vec![None, Some("headless")],
            "both linux/x64 builds are returned, the default (no variant) first"
        );
        // The pre-#1912 accessor is unchanged: it still resolves to the DEFAULT build only, so a
        // caller that never learned about variants keeps installing the default.
        assert_eq!(c.artifact("linux", "x64").unwrap().variant, None);
        // A platform with no build for it yields nothing (not a panic, not the wrong platform).
        assert_eq!(c.artifacts_for("windows", "x64").count(), 0);
    }

    /// SIGNATURE COMPAT (the load-bearing #1912 invariant): a schema-2 manifest whose artifact
    /// carries a `variant` still verifies over its RECEIVED bytes under the signing key — the
    /// `variant` token travels inside the signed payload verbatim and an older reader ignoring the
    /// key would compute the same signed bytes it did before.
    #[test]
    fn a_schema_2_manifest_carrying_a_variant_verifies_over_its_received_bytes() {
        use ed25519_dalek::Verifier;

        let key = targets_key();
        let mut m = sample_manifest();
        m.schema = 2;
        m.components[0].artifacts.push(headless_variant());

        let signed = SignedManifest::sign(m, &key);
        let json = signed.to_json();
        assert!(
            json.contains("\"variant\":\"headless\""),
            "the variant token is carried on the wire verbatim: {json}"
        );

        let parsed = SignedManifest::from_json(&json).expect("valid envelope");
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&parsed.signature)
            .expect("signature is base64");
        let signature =
            ed25519_dalek::Signature::from_slice(&sig_bytes).expect("64-byte signature");
        key.verifying_key()
            .verify(parsed.signed_payload(), &signature)
            .expect("a schema-2 manifest carrying a variant verifies over its received bytes");

        assert_eq!(
            parsed.manifest.components[0].artifacts[0].variant, None,
            "the default artifact still carries no variant"
        );
        assert_eq!(
            parsed.manifest.components[0].artifacts[1]
                .variant
                .as_deref(),
            Some("headless"),
        );
    }

    /// BACK-COMPAT: a pre-#1912 artifact JSON has no `variant` key at all — it must read as `None`,
    /// and a single-variant manifest must re-serialize WITHOUT the key (so the feed's byte-exact
    /// output is unperturbed and the signature over it is unchanged).
    #[test]
    fn an_artifact_without_a_variant_key_reads_as_none_and_reserializes_without_it() {
        let m = sample_manifest();
        let json = serde_json::to_string(&m).expect("serializable");
        assert!(
            !json.contains("variant"),
            "skip_serializing_if keeps a single-variant manifest byte-identical: {json}"
        );
        let back: Manifest = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(
            back.components[0].artifacts[0].variant, None,
            "an absent variant key defaults to the default build"
        );
    }
}
