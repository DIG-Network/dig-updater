//! `feedsign doctor` (dig_ecosystem#2115): validate `feed-config.json` against a channel's live
//! releases WITHOUT the signing secret, reported per component.
//!
//! A releasing component's published release can silently lack the asset kind `feed-config.json`
//! declares for it (the #618 case: dig-node configured `native_package` while its nightly shipped
//! only raw binaries). Before this, that mismatch was caught ONLY inside the signing pass
//! ([`crate::produce_feed`], which needs `BEACON_SIGNING_KEY`), so the only signal was a red nightly
//! Feed cron — which ran red unnoticed for three weeks.
//!
//! Doctor reuses the SAME per-component resolution [`crate::resolve_all`] the signer uses, so it can
//! never disagree with what signing would find, and it needs no key: it resolves each component for
//! a channel, reports every outcome, and fails if ANY component cannot resolve its declared assets
//! (respecting `exempt_platforms`, dig_ecosystem#2343).

use crate::channel::Channel;
use crate::config::FeedConfig;
use crate::resolve::ResolvedArtifact;
use crate::source::ReleaseSource;
use crate::{resolve_all, ComponentResolution};

/// A secret-free, per-component health report of one channel's `feed-config.json` resolution.
///
/// Produced by [`DoctorReport::run`] from the SAME [`resolve_all`] the signer drives — a doctor pass
/// therefore sees exactly what `produce_feed` would, minus the download + sign steps (so no key).
#[derive(Debug)]
pub struct DoctorReport {
    channel: Channel,
    components: Vec<ComponentResolution>,
}

impl DoctorReport {
    /// Resolve every configured component for `channel` and record each outcome — never failing on
    /// the first, so the report covers the WHOLE feed's health in one pass.
    #[must_use]
    pub fn run(config: &FeedConfig, source: &dyn ReleaseSource, channel: Channel) -> Self {
        Self {
            channel,
            components: resolve_all(config, source, channel),
        }
    }

    /// `true` when every component resolved its declared assets (a missing platform that is declared
    /// `exempt_platforms` does not count as a failure — [`crate::select_artifacts`] tolerates it).
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.components.iter().all(|c| c.outcome.is_ok())
    }

    /// A legible, secret-free report — one line per component (its resolved version + the platforms
    /// it resolved, or the resolution error, which itself names the component + the missing
    /// platforms) plus a one-line verdict. Suitable for a CI log; it reads no secret.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("feed doctor — channel: {}\n", self.channel.as_str());
        for component in &self.components {
            match &component.outcome {
                Ok(resolved) => out.push_str(&format!(
                    "  OK   {} {} — {}\n",
                    component.name,
                    resolved.version,
                    render_platforms(&resolved.artifacts),
                )),
                Err(error) => out.push_str(&format!("  FAIL {} — {error}\n", component.name)),
            }
        }
        let failures = self
            .components
            .iter()
            .filter(|c| c.outcome.is_err())
            .count();
        if failures == 0 {
            out.push_str("all components resolve.\n");
        } else {
            out.push_str(&format!(
                "{failures} of {} component(s) failed resolution.\n",
                self.components.len()
            ));
        }
        out
    }
}

/// The `os/arch` platforms a component resolved, comma-joined, annotating any non-default variant.
fn render_platforms(artifacts: &[ResolvedArtifact]) -> String {
    artifacts
        .iter()
        .map(|a| match &a.variant {
            Some(variant) => format!("{}/{} ({variant})", a.os, a.arch),
            None => format!("{}/{}", a.os, a.arch),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
