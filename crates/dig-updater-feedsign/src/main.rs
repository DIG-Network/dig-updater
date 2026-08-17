#![forbid(unsafe_code)]

//! The `dig-updater-feedsign` CI binary: assemble + sign the beacon feed, write it out, print a
//! secret-free summary.
//!
//! ## Four modes
//!
//! - **`doctor`** (subcommand, or `--doctor`) — validate `feed-config.json` against each component's
//!   LIVE releases for a channel WITHOUT any signing key (dig_ecosystem#2115), printing a
//!   per-component report and exiting non-zero if any component's release lacks the asset kind it
//!   declares. Run in CI BEFORE signing so a broken declaration fails as a named report, not a silent
//!   red at the signing step. Reads `--config`/`--channel`/`GITHUB_TOKEN` only.
//! - **`audit-exemptions`** (subcommand, or `--audit-exemptions`) — check every declared
//!   `exempt_platforms` against BOTH channels' live releases WITHOUT any signing key
//!   (dig_ecosystem#2555), exiting non-zero only on an exemption whose platform is resolvable in
//!   EVERY signed channel (droppable — it masks the #2343 gate everywhere). A platform resolvable in
//!   only a subset of channels is a NON-failing informational note (the exemption stays load-bearing
//!   for the channels that lack it). Reads `--config`/`GITHUB_TOKEN` only; always sweeps both
//!   channels. A PR/scheduled drift guard.
//! - **`audit-freshness`** (subcommand, or `--audit-freshness`) — compare what the LIVE feed serves
//!   against what each component's repo RELEASED, for one channel (dig_ecosystem#3046), exiting
//!   non-zero on any disagreement OR on any component it could not check. Users install from the
//!   feed, not from the GitHub Release, so this is the only check that asks whether a release
//!   actually reached them — every other check passes while the two disagree. Needs no signing key;
//!   reads `--config`/`--channel`/`--feed-base`/`GITHUB_TOKEN`.
//! - **default (sign)** — the full assemble + sign pass below (requires `BEACON_SIGNING_KEY`).
//!
//! Inputs (CLI flag falls back to environment):
//!
//! | purpose            | flag           | env                     | default            |
//! |--------------------|----------------|-------------------------|--------------------|
//! | config file        | `--config`          | `FEEDSIGN_CONFIG`           | `feed-config.json` |
//! | output directory   | `--out`             | `FEEDSIGN_OUT`              | `feed-out`         |
//! | channel            | `--channel`         | `FEEDSIGN_CHANNEL`          | `stable`           |
//! | transparency dir   | `--transparency-out`| `FEEDSIGN_TRANSPARENCY_OUT` | (optional)         |
//! | generated unix ts  | `--generated`       | `FEEDSIGN_GENERATED`        | (required)         |
//! | signing key (PEM/…)| —                   | `BEACON_SIGNING_KEY`        | (required)         |
//! | GitHub token       | —                   | `GITHUB_TOKEN`              | (optional)         |
//! | served feed base   | `--feed-base`       | `FEEDSIGN_FEED_BASE`        | `https://updates.dig.net` |
//!
//! `--channel stable|nightly` selects which of the two independent feeds to produce (SPEC §10.1);
//! the workflow runs the signer once per channel. It defaults to `stable` (the legacy behavior —
//! `releases/latest`) so an invocation with no channel keeps working.
//!
//! When `--transparency-out` is set, the signer also writes the transparency-log triple (signed
//! bytes + detached signature + targets public-key PEM) there, for the workflow to upload to a
//! public transparency log (Rekor, #533). It is optional so the offline signer + tests never need
//! it; the feed itself is unaffected either way.
//!
//! The `generated` timestamp is REQUIRED and never defaulted to the clock, so a run is
//! deterministic + reproducible (SPEC §10): the workflow supplies `date +%s`.
//!
//! Secret hygiene: `BEACON_SIGNING_KEY` is read from the environment, parsed, and used only to
//! sign. It is NEVER echoed; the only output is the [`SignedFeed::summary`] (sequence, timestamp,
//! public digests).

use std::process::ExitCode;

use dig_updater_feedsign::{
    assert_pinned_root, audit_exemptions, audit_freshness, produce_feed, signing_key_from_secret,
    Channel, DoctorReport, FeedConfig, FeedsignError, GithubSource, ReleaseSource, ServedFeed,
};

/// Where the served feed is read from when `--feed-base` is not given — the beacon's own primary
/// origin, so the audit checks the bytes real clients receive.
const DEFAULT_FEED_BASE: &str = "https://updates.dig.net";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // `doctor` (dig_ecosystem#2115) validates feed-config against live releases WITHOUT the signing
    // key, so it must dispatch BEFORE the signing pass (which requires BEACON_SIGNING_KEY). It exits
    // FAILURE if any component cannot resolve its declared assets.
    if is_doctor(&args) {
        return match run_doctor(&args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("dig-updater-feedsign doctor: {e}");
                ExitCode::FAILURE
            }
        };
    }

    // `--audit-exemptions` (dig_ecosystem#2555) checks every declared `exempt_platforms` against
    // BOTH channels' live releases and exits non-zero on any OVER-BROAD exemption. Like doctor it
    // needs NO signing key, so it dispatches before the signing pass and is CI-runnable on a PR.
    if is_audit_exemptions(&args) {
        return match run_audit_exemptions(&args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("dig-updater-feedsign audit-exemptions: {e}");
                ExitCode::FAILURE
            }
        };
    }

    // `audit-freshness` (dig_ecosystem#3046) compares the LIVE feed against each repo's release and
    // exits non-zero on any disagreement or un-checkable component. Read-only and secret-free, so
    // it dispatches before the signing pass. A transport failure reading the feed is an ERROR, never
    // a pass — the whole point is to refuse to report fresh from a check that did not happen.
    if is_audit_freshness(&args) {
        return match run_audit_freshness(&args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("dig-updater-feedsign audit-freshness: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match run(&args) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("dig-updater-feedsign: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Whether this invocation selects doctor mode: the `doctor` subcommand as the first argument, or a
/// `--doctor` flag anywhere.
fn is_doctor(args: &[String]) -> bool {
    args.first().is_some_and(|a| a == "doctor") || args.iter().any(|a| a == "--doctor")
}

/// The doctor pass: resolve every component of `--config`/`FEEDSIGN_CONFIG` for `--channel` against
/// live GitHub releases (needing NO signing key), print the per-component report, and return
/// [`ExitCode::FAILURE`] if any component fails resolution.
fn run_doctor(args: &[String]) -> Result<ExitCode, FeedsignError> {
    let config_path = input(args, "--config", "FEEDSIGN_CONFIG")
        .unwrap_or_else(|| "feed-config.json".to_string());
    let channel = match input(args, "--channel", "FEEDSIGN_CHANNEL") {
        Some(token) => Channel::from_token(&token)?,
        None => Channel::Stable,
    };

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|e| FeedsignError::Config(format!("{config_path}: {e}")))?;
    let config = FeedConfig::from_json(&config_text)?;

    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let source = GithubSource::github(token);

    let report = DoctorReport::run(&config, &source, channel);
    print!("{}", report.render());
    Ok(if report.is_healthy() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Whether this invocation selects exemption-audit mode: the `audit-exemptions` subcommand as the
/// first argument, or an `--audit-exemptions` flag anywhere.
fn is_audit_exemptions(args: &[String]) -> bool {
    args.first().is_some_and(|a| a == "audit-exemptions")
        || args.iter().any(|a| a == "--audit-exemptions")
}

/// The exemption-audit pass (dig_ecosystem#2555): check every component's `exempt_platforms` against
/// BOTH channels' live releases (needing NO signing key), print the report, and return
/// [`ExitCode::FAILURE`] if any exemption is over-broad. It reads only `--config`/`FEEDSIGN_CONFIG`
/// and `GITHUB_TOKEN`; the channel is not selectable — the audit always sweeps both.
fn run_audit_exemptions(args: &[String]) -> Result<ExitCode, FeedsignError> {
    let config_path = input(args, "--config", "FEEDSIGN_CONFIG")
        .unwrap_or_else(|| "feed-config.json".to_string());

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|e| FeedsignError::Config(format!("{config_path}: {e}")))?;
    let config = FeedConfig::from_json(&config_text)?;

    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let source = GithubSource::github(token);

    let audit = audit_exemptions(&config, &source);
    print!("{}", audit.render());
    Ok(if audit.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Whether this invocation selects freshness-audit mode: the `audit-freshness` subcommand as the
/// first argument, or an `--audit-freshness` flag anywhere.
fn is_audit_freshness(args: &[String]) -> bool {
    args.first().is_some_and(|a| a == "audit-freshness")
        || args.iter().any(|a| a == "--audit-freshness")
}

/// The served-vs-released freshness audit (dig_ecosystem#3046): read the live feed for `--channel`,
/// compare each configured component's served version against the version its repo released, print
/// the report, and return [`ExitCode::FAILURE`] on any disagreement or un-checkable component.
///
/// The manifest is read as DATA (no signature check) purely to learn which version is on offer;
/// authenticity is the beacon's pinned-key concern, not this audit's. Any failure to READ it
/// propagates as an error rather than an empty feed view, so a fetch that never happened can never
/// be mistaken for a feed that serves nothing — or for one that is fine.
fn run_audit_freshness(args: &[String]) -> Result<ExitCode, FeedsignError> {
    let config_path = input(args, "--config", "FEEDSIGN_CONFIG")
        .unwrap_or_else(|| "feed-config.json".to_string());
    let channel = match input(args, "--channel", "FEEDSIGN_CHANNEL") {
        Some(token) => Channel::from_token(&token)?,
        None => Channel::Stable,
    };
    let feed_base = input(args, "--feed-base", "FEEDSIGN_FEED_BASE")
        .unwrap_or_else(|| DEFAULT_FEED_BASE.to_string());

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|e| FeedsignError::Config(format!("{config_path}: {e}")))?;
    let config = FeedConfig::from_json(&config_text)?;

    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let source = GithubSource::github(token);

    // The exact URL a beacon fetches for this channel, so the audit judges the bytes real clients
    // receive rather than a re-derivation of them.
    let manifest_url = format!(
        "{}/v1/{}/manifest.json",
        feed_base.trim_end_matches('/'),
        channel.as_str()
    );
    let bytes = source.download(&manifest_url)?;
    let json = String::from_utf8(bytes)
        .map_err(|e| FeedsignError::Config(format!("{manifest_url}: not UTF-8: {e}")))?;
    let served = ServedFeed::from_manifest_json(&json)?;

    let audit = audit_freshness(&config, &source, &served, channel);
    print!("{}", audit.render());
    Ok(if audit.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The whole signing pass; returns the secret-free summary on success.
fn run(args: &[String]) -> Result<String, FeedsignError> {
    let config_path = input(args, "--config", "FEEDSIGN_CONFIG")
        .unwrap_or_else(|| "feed-config.json".to_string());
    let out_dir = input(args, "--out", "FEEDSIGN_OUT").unwrap_or_else(|| "feed-out".to_string());
    let channel = match input(args, "--channel", "FEEDSIGN_CHANNEL") {
        Some(token) => Channel::from_token(&token)?,
        None => Channel::Stable,
    };
    let generated = input(args, "--generated", "FEEDSIGN_GENERATED")
        .ok_or_else(|| {
            FeedsignError::MissingInput(
                "--generated / FEEDSIGN_GENERATED (unix seconds)".to_string(),
            )
        })?
        .trim()
        .parse::<u64>()
        .map_err(|e| {
            FeedsignError::MissingInput(format!("generated timestamp must be unix seconds: {e}"))
        })?;

    let secret = std::env::var("BEACON_SIGNING_KEY").map_err(|_| {
        FeedsignError::MissingInput("BEACON_SIGNING_KEY (the signing secret)".to_string())
    })?;
    let signing_key = signing_key_from_secret(&secret)?;
    // Refuse to sign under anything but the pinned root key — a feed signed otherwise would verify
    // under no shipped beacon (fail closed, never silently wrong).
    assert_pinned_root(&signing_key)?;

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|e| FeedsignError::Config(format!("{config_path}: {e}")))?;
    let config = FeedConfig::from_json(&config_text)?;

    let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
    let source = GithubSource::github(token);

    let feed = produce_feed(&config, &source, channel, generated, &signing_key)?;
    feed.write_to(std::path::Path::new(&out_dir))?;

    // Optionally emit the transparency-log triple for a public log (Rekor, #533). Derived from the
    // signed feed, so it can only reflect exactly what was published.
    if let Some(dir) = input(args, "--transparency-out", "FEEDSIGN_TRANSPARENCY_OUT") {
        feed.transparency()?.write_to(std::path::Path::new(&dir))?;
    }

    Ok(feed.summary())
}

/// A CLI `--flag <value>` if present, else the environment variable, else `None`.
fn input(args: &[String], flag: &str, env: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| std::env::var(env).ok())
}
