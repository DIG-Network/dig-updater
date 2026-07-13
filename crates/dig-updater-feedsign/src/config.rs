//! The committed feed configuration (`feed-config.json`): which components the feed tracks, and
//! the manifest-level knobs (schema, delegation version, freshness windows, rollback floor).
//!
//! Everything a maintainer tunes about the feed lives in ONE committed, reviewable file — never
//! baked into the signer — so a floor bump or a new component is an auditable diff, not a code
//! change. The per-run `generated`/`sequence` timestamp is NOT here: it is supplied by the
//! workflow at signing time (determinism, SPEC §10).

use serde::Deserialize;

use crate::error::FeedsignError;

/// The manifest schema version this signer emits. Additive-only (SPEC §5.2).
const DEFAULT_SCHEMA: u32 = 1;
/// The alpha delegation version (root == targets; a single generation). SPEC §4.3.
const DEFAULT_ROOT_VERSION: u32 = 1;
/// Default manifest lifetime: 12 hours (SPEC §7 heartbeat). With a 6-hour signing cadence this
/// leaves 6 hours of slack, so a single skipped run never lets clients see an expired feed.
const DEFAULT_MANIFEST_TTL_SECS: u64 = 12 * 60 * 60;
/// Default delegation lifetime: 30 days. Re-emitted on every run, so it is always well ahead of
/// expiry; kept much longer than the manifest because rotating the targets key is rare.
const DEFAULT_DELEGATION_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// The signed feed's configuration, parsed from `feed-config.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct FeedConfig {
    /// The manifest schema version to emit.
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// The delegation `root_version` to emit (alpha: a single generation, `1`).
    #[serde(default = "default_root_version")]
    pub root_version: u32,
    /// The anti-downgrade floor: no component build below this may install (SPEC §7.5). Alpha
    /// default `0` (nothing is floored out yet); raised deliberately to retire a vulnerable build.
    #[serde(default)]
    pub rollback_floor_build: u64,
    /// Seconds the signed manifest stays valid after `generated` (SPEC §7 heartbeat).
    #[serde(default = "default_manifest_ttl")]
    pub manifest_ttl_secs: u64,
    /// Seconds the signed delegation stays valid after `generated`.
    #[serde(default = "default_delegation_ttl")]
    pub delegation_ttl_secs: u64,
    /// The components the feed tracks, in the order they appear in the manifest.
    pub components: Vec<ComponentConfig>,
}

/// One tracked component: its manifest name and where to resolve its latest release.
#[derive(Debug, Clone, Deserialize)]
pub struct ComponentConfig {
    /// The component id as it appears in the manifest and matches the installed component
    /// (e.g. `dig-node`).
    pub name: String,
    /// The GitHub `owner/repo` whose latest release supplies this component's build.
    pub repo: String,
    /// The release-asset name prefix that identifies this component's binaries. An asset is a
    /// match when its name is exactly `{asset_prefix}-{version}-{platform-token}` (e.g.
    /// `dig-node-0.29.0-linux-x64`), which excludes sibling artifacts like the `.tar.gz` source
    /// bundles or a differently-named companion binary in the same release.
    pub asset_prefix: String,
}

fn default_schema() -> u32 {
    DEFAULT_SCHEMA
}
fn default_root_version() -> u32 {
    DEFAULT_ROOT_VERSION
}
fn default_manifest_ttl() -> u64 {
    DEFAULT_MANIFEST_TTL_SECS
}
fn default_delegation_ttl() -> u64 {
    DEFAULT_DELEGATION_TTL_SECS
}

impl FeedConfig {
    /// Parse a [`FeedConfig`] from JSON text.
    ///
    /// # Errors
    ///
    /// [`FeedsignError::Config`] if the text is not valid JSON, or if it lists no components (a
    /// feed with nothing to sign is a misconfiguration, not a valid empty feed).
    pub fn from_json(json: &str) -> Result<Self, FeedsignError> {
        let config: Self =
            serde_json::from_str(json).map_err(|e| FeedsignError::Config(e.to_string()))?;
        if config.components.is_empty() {
            return Err(FeedsignError::Config(
                "no components configured — nothing to sign".to_string(),
            ));
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let json = r#"{
            "schema": 1,
            "root_version": 1,
            "rollback_floor_build": 5,
            "manifest_ttl_secs": 3600,
            "delegation_ttl_secs": 86400,
            "components": [
                { "name": "dig-node", "repo": "DIG-Network/dig-node", "asset_prefix": "dig-node" }
            ]
        }"#;
        let c = FeedConfig::from_json(json).unwrap();
        assert_eq!(c.schema, 1);
        assert_eq!(c.rollback_floor_build, 5);
        assert_eq!(c.manifest_ttl_secs, 3600);
        assert_eq!(c.delegation_ttl_secs, 86400);
        assert_eq!(c.components.len(), 1);
        assert_eq!(c.components[0].repo, "DIG-Network/dig-node");
    }

    #[test]
    fn applies_defaults_when_omitted() {
        let json = r#"{
            "components": [
                { "name": "dig-node", "repo": "DIG-Network/dig-node", "asset_prefix": "dig-node" }
            ]
        }"#;
        let c = FeedConfig::from_json(json).unwrap();
        assert_eq!(c.schema, 1);
        assert_eq!(c.root_version, 1);
        assert_eq!(c.rollback_floor_build, 0);
        assert_eq!(c.manifest_ttl_secs, 12 * 60 * 60);
        assert_eq!(c.delegation_ttl_secs, 30 * 24 * 60 * 60);
    }

    #[test]
    fn rejects_empty_components() {
        let json = r#"{ "components": [] }"#;
        assert!(matches!(
            FeedConfig::from_json(json),
            Err(FeedsignError::Config(_))
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(matches!(
            FeedConfig::from_json("{not json"),
            Err(FeedsignError::Config(_))
        ));
    }
}
