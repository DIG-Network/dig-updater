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
//! - **`drift`** (subcommand, or `--drift`) — compare the versions a channel's releases supply
//!   against the versions the LIVE feed at `--feed-base` actually serves (dig_ecosystem#3046),
//!   WITHOUT any signing key, exiting non-zero when the published feed is behind (or ahead of) the
//!   releases. Doctor validates a feed's INPUTS; drift validates the OUTPUT beacons are served — a
//!   feed can be six hours stale with a fully green doctor, which is the outage this catches. Reads
//!   `--config`/`--channel`/`--feed-base`/`GITHUB_TOKEN` only.
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
//! | live feed base     | `--feed-base`       | `FEEDSIGN_FEED_BASE`        | `https://updates.dig.net/v1` |
//! | signing key (PEM/…)| —                   | `BEACON_SIGNING_KEY`        | (required)         |
//! | GitHub token       | —                   | `GITHUB_TOKEN`              | (optional)         |
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
    assert_pinned_root, audit_exemptions, check_drift, manifest_url_for, produce_feed,
    signing_key_from_secret, Channel, DoctorReport, FeedConfig, FeedsignError, GithubSource,
};

/// The production feed base — the `/v1` root under which each channel publishes its
/// `{channel}/manifest.json` (SPEC §10). Overridable so tests and staging can point elsewhere.
const DEFAULT_FEED_BASE: &str = "https://updates.dig.net/v1";

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

    // `drift` (dig_ecosystem#3046) compares the LIVE served feed against the channel's releases. Like
    // doctor it needs NO signing key — which is the point: it runs on a short interval in an
    // unprivileged workflow, so the frequent poller never has the key in scope.
    if is_drift(&args) {
        return match run_drift(&args) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("dig-updater-feedsign drift: {e}");
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

/// Whether this invocation selects drift mode: the `drift` subcommand as the first argument, or a
/// `--drift` flag anywhere.
fn is_drift(args: &[String]) -> bool {
    args.first().is_some_and(|a| a == "drift") || args.iter().any(|a| a == "--drift")
}

/// The drift pass: resolve every component's `--channel` release, fetch the manifest the live feed
/// serves at `--feed-base`, print the comparison, and return [`ExitCode::FAILURE`] when the served
/// feed does not provably match the releases.
///
/// A FAILURE here is not a broken feed — it is a feed that has not been regenerated since the last
/// release. The workflow's response is to dispatch the Feed workflow, not to page anyone.
fn run_drift(args: &[String]) -> Result<ExitCode, FeedsignError> {
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

    let report = check_drift(
        &config,
        &source,
        channel,
        &manifest_url_for(&feed_base, channel),
    )?;
    // `--json` (§6.2) is what an automated responder reads: it keys on `regenerable` to decide
    // whether dispatching the Feed workflow would actually fix what was found.
    if args.iter().any(|a| a == "--json") {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.render());
    }
    Ok(if report.is_current() {
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
