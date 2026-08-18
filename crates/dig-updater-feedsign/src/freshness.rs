//! The SERVED-vs-RELEASED freshness audit (dig_ecosystem#3046).
//!
//! # The question nothing else was asking
//!
//! Users install from the FEED, not from the GitHub Release. Those two can disagree, and when they
//! do, every check the ecosystem already runs still passes: the tag exists, it is marked latest,
//! its assets are all present and correctly digested. A release-watcher verifying the release — the
//! right thing to verify — reports GREEN while no user can obtain the build.
//!
//! That is a whole defect CLASS, not one bug: **a release step that silently does not run, invisible
//! because nothing turns red.** The same shape has appeared as a feed with no trigger but a 6-hour
//! cron, as a `workflow_dispatch` selected against the wrong ref that skipped its publish job while
//! reporting `completed`, and as a publish workflow keyed to a tag pattern that was never once
//! pushed. In every case the release pipeline reports success and the artifact never reaches users.
//!
//! One question catches all of them, because it skips the pipeline entirely and compares the two
//! ENDS: *does the version being served match the version the repo believes it released?* This
//! module asks exactly that, and REDs when the answer is no or unknown.
//!
//! # What this audit is NOT
//!
//! It makes **no trust claim** about the served manifest. It reads the manifest as DATA to learn
//! which version is on offer; it does not verify the signature, and a green audit says nothing
//! about the feed's authenticity — that is the beacon's pinned-key verification, and the signing
//! keystone in `feed.yml`. Conversely a red audit is about CONTENT being stale, never about trust.
//!
//! It is read-only and secret-free (public release metadata + the public manifest), so it runs off
//! the signing path entirely.
//!
//! # Refusing to report green
//!
//! Most of the care here is spent on NOT answering "current" when the audit does not know. A
//! staleness check that passes when it could not reach a release, when a component is absent from
//! the manifest, or when it was handed nothing to check would be worse than no check at all — it
//! would answer the one question that matters with a confident, wrong "yes". So an unreachable
//! release, an absent component, and an empty component list are each NOT clean.

use std::collections::BTreeMap;

use dig_updater_trust::SignedManifest;

use crate::channel::Channel;
use crate::config::FeedConfig;
use crate::error::FeedsignError;
use crate::resolve_release_and_version;
use crate::source::ReleaseSource;

/// The versions a live feed is currently OFFERING, read from a served manifest.
///
/// Parsed through the canonical [`SignedManifest`] type the beacon itself uses, so this cannot
/// drift from the real wire shape — a second hand-rolled parser of the same bytes is exactly how
/// two readers of one format end up disagreeing.
#[derive(Debug, Clone)]
pub struct ServedFeed {
    /// `component name -> served version`.
    versions: BTreeMap<String, String>,
}

impl ServedFeed {
    /// Read the served versions out of a signed manifest's JSON.
    ///
    /// The signature is NOT checked: this asks what is being offered, not whether it is authentic
    /// (see the module docs). Parsing still fails closed — a malformed manifest is an error, never
    /// an empty-but-usable view that would read as "every component is missing".
    ///
    /// # Errors
    ///
    /// [`FeedsignError::Config`] if the JSON is not a well-formed signed manifest.
    pub fn from_manifest_json(json: &str) -> Result<Self, FeedsignError> {
        let signed = SignedManifest::from_json(json)
            .map_err(|e| FeedsignError::Config(format!("served manifest: {e}")))?;
        Ok(Self {
            versions: signed
                .manifest
                .components
                .into_iter()
                .map(|c| (c.name, c.version))
                .collect(),
        })
    }

    /// The version this feed serves for `component`, or `None` when it offers that component at all.
    #[must_use]
    pub fn version_of(&self, component: &str) -> Option<&str> {
        self.versions.get(component).map(String::as_str)
    }
}

/// One component's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// The feed serves exactly the released version — users can get what was released.
    Current {
        /// The version both ends agree on.
        version: String,
    },
    /// The feed and the release DISAGREE, in either direction, including the feed not offering the
    /// component at all (`served: None`). Whatever the cause, users cannot obtain the release.
    Diverged {
        /// The version the repo released for this channel.
        released: String,
        /// The version the feed serves, or `None` when it does not offer the component.
        served: Option<String>,
    },
    /// The audit COULD NOT ASK — the release was unreachable or unparseable. Distinct from
    /// [`Freshness::Diverged`] because it demands a different response: re-run or fix the check,
    /// rather than fix the feed.
    Unknown {
        /// Why the released version could not be established.
        detail: String,
    },
}

impl Freshness {
    /// Whether this verdict is a healthy one. Only [`Freshness::Current`] is.
    #[must_use]
    pub fn is_current(&self) -> bool {
        matches!(self, Freshness::Current { .. })
    }
}

/// One component's name paired with its verdict.
#[derive(Debug, Clone)]
pub struct ComponentFreshness {
    /// The component name, as it appears in both the config and the manifest.
    pub name: String,
    /// What the audit found for it.
    pub freshness: Freshness,
}

/// A secret-free audit comparing what the live feed SERVES against what each component's repo
/// RELEASED, for one channel (dig_ecosystem#3046).
#[derive(Debug)]
pub struct FreshnessAudit {
    channel: Channel,
    findings: Vec<ComponentFreshness>,
}

impl FreshnessAudit {
    /// Compare every configured component's `channel` release against the version `served` offers.
    ///
    /// Iteration is over the CONFIG, never over the manifest's entries: a component the feed has
    /// dropped entirely must be a finding, and iterating what the feed happens to contain would
    /// silently skip precisely the worst case.
    #[must_use]
    pub fn run(
        config: &FeedConfig,
        source: &dyn ReleaseSource,
        served: &ServedFeed,
        channel: Channel,
    ) -> Self {
        let findings = config
            .components
            .iter()
            .map(|component| ComponentFreshness {
                name: component.name.clone(),
                freshness: match resolve_release_and_version(source, component, channel) {
                    Err(e) => Freshness::Unknown {
                        detail: e.to_string(),
                    },
                    Ok((_, released)) => match served.version_of(&component.name) {
                        Some(served) if served == released => {
                            Freshness::Current { version: released }
                        }
                        served => Freshness::Diverged {
                            released,
                            served: served.map(str::to_string),
                        },
                    },
                },
            })
            .collect();
        Self { channel, findings }
    }

    /// `true` only when the audit actually CHECKED something and every component it checked is
    /// current.
    ///
    /// The non-empty requirement is not pedantry: "no component is stale" is trivially true of an
    /// empty component list, so without it a config that checks nothing would report a confident
    /// green forever — the same silent-success shape this audit exists to catch.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        !self.findings.is_empty() && self.findings.iter().all(|f| f.freshness.is_current())
    }

    /// Every component's verdict, in config order.
    #[must_use]
    pub fn findings(&self) -> &[ComponentFreshness] {
        &self.findings
    }

    /// A legible, secret-free report naming BOTH versions for every disagreement, so the drift is
    /// actionable straight from the log without re-deriving it.
    #[must_use]
    pub fn render(&self) -> String {
        let channel = self.channel.as_str();
        let mut out = format!(
            "feed freshness audit — {channel} channel (dig_ecosystem#3046)\n\
             does the version the feed SERVES match the version each repo RELEASED?\n"
        );

        if self.findings.is_empty() {
            out.push_str(
                "  NOTHING CHECKED — the config declares no components, so this audit proved \
                 nothing.\n",
            );
            return out;
        }

        for finding in &self.findings {
            out.push_str(&render_finding(finding));
        }

        let diverged = self.count(|f| matches!(f, Freshness::Diverged { .. }));
        let unknown = self.count(|f| matches!(f, Freshness::Unknown { .. }));
        out.push_str(&match (diverged, unknown) {
            (0, 0) => {
                format!("every component's {channel} feed entry matches its released version.\n")
            }
            (0, u) => format!(
                "{u} component(s) COULD NOT BE CHECKED — this audit does not know whether the \
                 {channel} feed is current.\n"
            ),
            (d, 0) => format!(
                "{d} component(s) released a version the {channel} feed does not serve — users \
                 cannot obtain that release. Confirm the release triggered the feed \
                 (`repository_dispatch: component-released`), then re-run the feed workflow.\n"
            ),
            (d, u) => format!(
                "{d} component(s) diverged and {u} could not be checked — users cannot obtain \
                 the diverged release(s), and the rest is unproven.\n"
            ),
        });
        out
    }

    /// How many findings match `predicate`.
    fn count(&self, predicate: impl Fn(&Freshness) -> bool) -> usize {
        self.findings
            .iter()
            .filter(|f| predicate(&f.freshness))
            .count()
    }
}

/// One finding's report line, always naming both sides of the comparison.
fn render_finding(finding: &ComponentFreshness) -> String {
    match &finding.freshness {
        Freshness::Current { version } => {
            format!("  CURRENT   {} — serving {version}\n", finding.name)
        }
        Freshness::Diverged {
            released,
            served: Some(served),
        } => format!(
            "  DIVERGED  {} — released {released}, feed serves {served}\n",
            finding.name
        ),
        Freshness::Diverged {
            released,
            served: None,
        } => format!(
            "  MISSING   {} — released {released}, feed does not offer this component at all\n",
            finding.name
        ),
        Freshness::Unknown { detail } => format!(
            "  UNCHECKED {} — could not establish the released version: {detail}\n",
            finding.name
        ),
    }
}
