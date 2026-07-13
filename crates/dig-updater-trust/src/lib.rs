#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # dig-updater-trust — the beacon trust core
//!
//! This crate is the security kernel of the DIG auto-update beacon. It defines the
//! wire types the beacon consumes and the verification surface it applies to them.
//! It performs **no I/O** — every function is pure and takes its inputs by value or
//! reference — so the whole trust model is exhaustively unit-testable.
//!
//! ## Trust invariant — the signature is the gate, not the transport
//!
//! Every installed byte chains, cryptographically, to the [root public key](pinned_key)
//! compiled into the beacon binary:
//!
//! 1. A [`SignedDelegation`] signed by the pinned **root** key names the current
//!    **targets** key (the key authorized to sign manifests).
//! 2. A [`SignedManifest`] signed by that **targets** key lists, per component and per
//!    OS/arch, the download URL and the **SHA-256** of the artifact bytes.
//! 3. Each downloaded artifact is verified byte-for-byte against that in-manifest digest
//!    ([`verify_artifact_digest`]) *before* it is handed to the privileged installer.
//!
//! Because the digest lives inside the signed manifest and the manifest chains to the
//! pinned root key, a hostile CDN, broken TLS, a stolen `RELEASE_TOKEN`, or a compromised
//! build runner cannot cause a malicious or downgraded artifact to be installed — none of
//! them holds a key that chains to the pinned root.
//!
//! ## Freshness — anti-rollback, anti-freeze, anti-downgrade
//!
//! A valid signature is necessary but not sufficient. A replayed-but-authentic *old*
//! manifest is an attack (freeze / downgrade). [`TrustState`] carries monotonic
//! high-water-marks (`root_version`, `sequence`, `generated`) plus a `rollback_floor_build`;
//! [`verify_freshness`] rejects any manifest that regresses them or that has expired. The
//! feed re-signs on a short cadence (heartbeat) with a short expiry, so a stalled/pinned
//! feed is detected rather than trusted forever.
//!
//! [`verify_update_chain`] composes the whole check in the order a caller must apply it.

pub mod manifest;
pub mod pinned_key;
pub mod trust_state;
pub mod verify;

pub use manifest::{Artifact, Component, Delegation, Manifest, SignedDelegation, SignedManifest};
pub use pinned_key::{beacon_root_verifying_key, BEACON_ROOT_PUBKEY_B64};
pub use trust_state::TrustState;
pub use verify::{
    verify_artifact_digest, verify_delegation, verify_freshness, verify_manifest_signature,
    verify_update_chain, TrustError,
};
