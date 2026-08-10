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
use crate::config::{FeedConfig, PlatformKey};
use crate::resolve::{overbroad_exemptions, ResolvedArtifact};
use crate::source::ReleaseSource;
use crate::{resolve_all, resolve_release_and_version, ComponentResolution};

/// Both channels, in report + iteration order — the fixed pair the feed publishes (SPEC §10.1).
const ALL_CHANNELS: [Channel; 2] = [Channel::Stable, Channel::Nightly];

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

/// One component's over-broad exemptions on ONE channel: the `exempt_platforms` entries whose asset
/// the channel's release actually publishes, so the exemption masks the #2343 completeness gate for
/// them (dig_ecosystem#2555). Empty when every declared exemption is still accurate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentExemptions {
    /// The component id from the config.
    pub name: String,
    /// The channel this finding is for.
    pub channel: Channel,
    /// The declared-exempt platforms that ARE resolvable on this channel — the over-broad ones.
    pub overbroad: Vec<PlatformKey>,
}

/// A secret-free audit of every component's `exempt_platforms` against BOTH channels' live releases,
/// flagging each exemption that has become OVER-BROAD — the platform is now resolvable, so the
/// exemption should be dropped lest it hide a future regression (dig_ecosystem#2555).
///
/// It is the OPPOSITE direction from the #2343 completeness gate: that gate REDs on a MISSING,
/// unexempted platform; this REDs on an EXEMPT, resolvable one. It never widens the gate's expected
/// set — a genuinely-missing platform still REDs [`crate::select_artifacts`] unchanged.
#[derive(Debug)]
pub struct ExemptionAudit {
    findings: Vec<ComponentExemptions>,
}

impl ExemptionAudit {
    /// Audit every component on both channels. A component whose release cannot be fetched or whose
    /// version cannot be parsed on a channel yields NO over-broad finding there — judging an
    /// exemption over-broad requires a resolvable release, and a genuine resolution failure is the
    /// [`DoctorReport`]/completeness gate's concern, not this drift check's.
    #[must_use]
    pub fn run(config: &FeedConfig, source: &dyn ReleaseSource) -> Self {
        let mut findings = Vec::new();
        for channel in ALL_CHANNELS {
            for component in &config.components {
                if component.exempt_platforms.is_empty() {
                    continue;
                }
                let Ok((release, version)) =
                    resolve_release_and_version(source, component, channel)
                else {
                    continue;
                };
                let overbroad = overbroad_exemptions(&release, component, &version);
                if !overbroad.is_empty() {
                    findings.push(ComponentExemptions {
                        name: component.name.clone(),
                        channel,
                        overbroad,
                    });
                }
            }
        }
        Self { findings }
    }

    /// `true` when no exemption is over-broad on either channel — every declared exemption still
    /// names a platform the component genuinely does not publish.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// The over-broad findings, one per `(component, channel)` that has any.
    #[must_use]
    pub fn findings(&self) -> &[ComponentExemptions] {
        &self.findings
    }

    /// A legible, secret-free report + a one-line verdict, suitable for a CI log. It reads no secret
    /// and names, per over-broad finding, the component, channel, and the resolvable platforms whose
    /// exemption should be dropped.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from("feed exemption audit (dig_ecosystem#2555)\n");
        if self.findings.is_empty() {
            out.push_str("all declared exemptions are accurate — no over-broad exemption.\n");
            return out;
        }
        for finding in &self.findings {
            out.push_str(&format!(
                "  OVER-BROAD {} [{}] — resolvable, drop the exemption for: {}\n",
                finding.name,
                finding.channel.as_str(),
                render_platform_keys(&finding.overbroad),
            ));
        }
        out.push_str(&format!(
            "{} over-broad exemption(s) — a resolvable platform is masking the #2343 gate.\n",
            self.findings.len()
        ));
        out
    }
}

/// `os/arch` platform keys, comma-joined, for the audit report.
fn render_platform_keys(platforms: &[PlatformKey]) -> String {
    platforms
        .iter()
        .map(|p| format!("{}/{}", p.os, p.arch))
        .collect::<Vec<_>>()
        .join(", ")
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
