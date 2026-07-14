//! The pinned beacon **root** public key.
//!
//! The root key's **public** half is compiled into every beacon binary here; its
//! **private** half exists only as the `feed-signing` GitHub Environment secret on
//! `DIG-Network/dig-updater`, scoped to the `main` branch, and is used by CI to sign the
//! update feed. The private key is NEVER committed to this repo and NEVER printed. The PEM
//! form of this same key is committed at `keys/beacon-root.pub` for out-of-band inspection.
//!
//! Pinning the key in the binary is what makes the signature — not the transport — the
//! gate: an attacker who controls the CDN, DNS, or TLS still cannot produce a manifest
//! that verifies under this key.
//!
//! ## Alpha-floor custody
//!
//! For the alpha channel this is a **single** Ed25519 root key whose private half lives
//! in an environment-scoped GitHub Actions secret (per the #504 alpha-floor clearance).
//! Before public launch this is hardened to a 2-of-N threshold with at least one offline
//! root and a KMS/HSM-backed signer, and this pinned key is rotated. That hardening is a
//! tracked follow-up, not part of the alpha; see SPEC.md § "Signing hierarchy".

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;

/// Base64 (standard alphabet, no line breaks) of the raw 32-byte Ed25519 **root** public
/// key pinned into the beacon.
///
/// This is the raw key, NOT the SubjectPublicKeyInfo DER — the PEM at `keys/beacon-root.pub`
/// wraps these same 32 bytes in the 12-byte Ed25519 SPKI header. The private half is the
/// `feed-signing` GitHub Environment secret; it is never in this repo.
pub const BEACON_ROOT_PUBKEY_B64: &str = "FIwQOAGI3D0pwEP2oAkvlOqEoM6LoxRliLUxQPjpeJ0=";

/// Decode [`BEACON_ROOT_PUBKEY_B64`] into an Ed25519 [`VerifyingKey`].
///
/// # Panics
///
/// Panics only if the compiled-in constant is not valid base64 of a valid 32-byte Ed25519
/// point — a build-time invariant guaranteed by the unit tests in this module, so this
/// never panics in a shipped binary.
#[must_use]
pub fn beacon_root_verifying_key() -> VerifyingKey {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(BEACON_ROOT_PUBKEY_B64)
        .expect("BEACON_ROOT_PUBKEY_B64 must be valid standard base64");
    let arr: [u8; 32] = bytes
        .try_into()
        .expect("pinned root key must decode to exactly 32 bytes");
    VerifyingKey::from_bytes(&arr).expect("pinned root key must be a valid Ed25519 point")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned constant decodes to exactly a 32-byte Ed25519 key.
    #[test]
    fn pinned_key_decodes_to_32_bytes() {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(BEACON_ROOT_PUBKEY_B64)
            .expect("valid base64");
        assert_eq!(raw.len(), 32, "Ed25519 public key must be 32 bytes");
    }

    /// The raw pinned constant matches the 32 key bytes embedded in the committed PEM
    /// (`keys/beacon-root.pub`), i.e. the SPKI DER = 12-byte Ed25519 header ++ raw key.
    #[test]
    fn pinned_key_matches_committed_pem() {
        // The single base64 line inside keys/beacon-root.pub (the SPKI DER).
        const PEM_DER_B64: &str = "MCowBQYDK2VwAyEAFIwQOAGI3D0pwEP2oAkvlOqEoM6LoxRliLUxQPjpeJ0=";
        // Standard Ed25519 SubjectPublicKeyInfo prefix (RFC 8410).
        const ED25519_SPKI_PREFIX: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];

        let der = base64::engine::general_purpose::STANDARD
            .decode(PEM_DER_B64)
            .expect("valid base64");
        assert_eq!(
            der.len(),
            44,
            "Ed25519 SPKI DER is 12 header + 32 key bytes"
        );
        assert_eq!(&der[..12], &ED25519_SPKI_PREFIX, "unexpected SPKI header");

        let raw = base64::engine::general_purpose::STANDARD
            .decode(BEACON_ROOT_PUBKEY_B64)
            .expect("valid base64");
        assert_eq!(
            &der[12..],
            raw.as_slice(),
            "PEM key bytes must equal the pinned raw key"
        );
    }

    /// The pinned key parses into a usable Ed25519 verifying key.
    #[test]
    fn beacon_root_verifying_key_is_a_valid_point() {
        let key = beacon_root_verifying_key();
        assert_eq!(key.to_bytes().len(), 32);
    }
}
