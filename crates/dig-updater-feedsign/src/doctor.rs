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
use crate::config::{ComponentConfig, FeedConfig, PlatformKey};
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

/// One `(component, platform)` exemption's cross-channel status: the channels whose release actually
/// publishes a feed-resolvable default asset for the exempt platform (dig_ecosystem#2555).
///
/// `exempt_platforms` is per-component and applies to EVERY channel the feed signs, so an exemption
/// is safe to DROP only when the platform is resolvable in ALL of them: if it resolves in a strict
/// SUBSET (e.g. dig-node's linux/arm64 in stable but not nightly), the exemption is still
/// LOAD-BEARING for the channel(s) that lack it — dropping it would RED the #2343 completeness gate
/// on those channels and break their live feed. So this records the set and lets
/// [`ComponentExemptions::is_droppable`] decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentExemptions {
    /// The component id from the config.
    pub name: String,
    /// The exempt platform this finding is about.
    pub platform: PlatformKey,
    /// The channels in which this platform is actually resolvable (the exemption is over-broad
    /// THERE), in [`ALL_CHANNELS`] order. Non-empty for every recorded finding.
    pub overbroad_channels: Vec<Channel>,
}

impl ComponentExemptions {
    /// `true` when the exemption is safe to DROP: the platform is resolvable in EVERY signed channel,
    /// so no channel still relies on the exemption to satisfy the #2343 gate. A strict-subset
    /// over-broad (resolvable in some channels, not others) is NOT droppable — the exemption remains
    /// load-bearing for the channels that lack the platform.
    #[must_use]
    pub fn is_droppable(&self) -> bool {
        ALL_CHANNELS
            .iter()
            .all(|channel| self.overbroad_channels.contains(channel))
    }
}

/// A secret-free audit of every component's `exempt_platforms` against BOTH channels' live releases
/// (dig_ecosystem#2555). An exemption is a FAILING finding — safe to drop — only when its platform is
/// resolvable in EVERY signed channel; a platform resolvable in only a strict subset of channels is
/// reported as an informational, NON-failing note (the exemption is still load-bearing elsewhere).
///
/// It is the OPPOSITE direction from the #2343 completeness gate: that gate REDs on a MISSING,
/// unexempted platform; this REDs on an EXEMPT platform that is resolvable in all channels. It never
/// widens the gate's expected set — a genuinely-missing platform still REDs [`crate::select_artifacts`]
/// unchanged.
#[derive(Debug)]
pub struct ExemptionAudit {
    findings: Vec<ComponentExemptions>,
}

impl ExemptionAudit {
    /// Audit every component's exemptions across both channels, aggregating per `(component,
    /// platform)`.
    ///
    /// A channel whose release cannot be fetched or whose version cannot be parsed counts as "does
    /// not resolve there" — so the exemption is CONSERVATIVELY retained for that channel (a genuine
    /// resolution failure is the [`DoctorReport`]/completeness gate's concern, and never a reason to
    /// recommend dropping an exemption the failing channel may still need).
    #[must_use]
    pub fn run(config: &FeedConfig, source: &dyn ReleaseSource) -> Self {
        let mut findings = Vec::new();
        for component in &config.components {
            for platform in &component.exempt_platforms {
                let overbroad_channels = channels_resolving(source, component, platform);
                if !overbroad_channels.is_empty() {
                    findings.push(ComponentExemptions {
                        name: component.name.clone(),
                        platform: platform.clone(),
                        overbroad_channels,
                    });
                }
            }
        }
        Self { findings }
    }

    /// `true` when NO exemption is over-broad in EVERY signed channel — i.e. no exemption is safe to
    /// drop. A partial/single-channel over-broad keeps the audit clean (its exemption stays
    /// load-bearing), so the CLI exit code is 0 for it.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.findings.iter().any(ComponentExemptions::is_droppable)
    }

    /// Every recorded finding — both the DROPPABLE (all-channel) ones and the informational
    /// partial-channel notes.
    #[must_use]
    pub fn findings(&self) -> &[ComponentExemptions] {
        &self.findings
    }

    /// A legible, secret-free report + a one-line verdict. It names each DROP finding (over-broad in
    /// every channel → drop the exemption) and each RETAINED note (over-broad in only some channels →
    /// exemption still load-bearing), then states whether any exemption is droppable.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from("feed exemption audit (dig_ecosystem#2555)\n");
        if self.findings.is_empty() {
            out.push_str("all declared exemptions are accurate — no over-broad exemption.\n");
            return out;
        }
        for finding in &self.findings {
            out.push_str(&render_finding(finding));
        }
        let droppable = self.findings.iter().filter(|f| f.is_droppable()).count();
        if droppable == 0 {
            out.push_str(
                "no over-broad exemption is resolvable in every channel — none is droppable.\n",
            );
        } else {
            out.push_str(&format!(
                "{droppable} exemption(s) resolvable in every signed channel — drop them; a resolvable platform masks the #2343 gate.\n",
            ));
        }
        out
    }
}

/// The channels (in [`ALL_CHANNELS`] order) whose release resolves `platform` for `component` — the
/// channels where the exemption is over-broad. A channel that cannot resolve at all is omitted, so
/// the exemption is treated as still needed there.
fn channels_resolving(
    source: &dyn ReleaseSource,
    component: &ComponentConfig,
    platform: &PlatformKey,
) -> Vec<Channel> {
    ALL_CHANNELS
        .iter()
        .copied()
        .filter(|&channel| {
            let Ok((release, version)) = resolve_release_and_version(source, component, channel)
            else {
                return false;
            };
            overbroad_exemptions(&release, component, &version).contains(platform)
        })
        .collect()
}

/// One finding's report line: `DROP` when resolvable in every channel (safe to drop), else `RETAINED`
/// with the channels it resolves in (still load-bearing for the others).
fn render_finding(finding: &ComponentExemptions) -> String {
    let platform = format!("{}/{}", finding.platform.os, finding.platform.arch);
    let channels = finding
        .overbroad_channels
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if finding.is_droppable() {
        format!(
            "  DROP     {} [{platform}] — resolvable in every signed channel ({channels}); drop the exemption\n",
            finding.name,
        )
    } else {
        format!(
            "  RETAINED {} [{platform}] — resolvable in {channels} but not every channel; exemption still load-bearing (per-channel exemptions would be needed to drop it)\n",
            finding.name,
        )
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
