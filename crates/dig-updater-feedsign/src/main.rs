#![forbid(unsafe_code)]

//! The `dig-updater-feedsign` CI binary: assemble + sign the beacon feed, write it out, print a
//! secret-free summary.
//!
//! Inputs (CLI flag falls back to environment):
//!
//! | purpose            | flag           | env                     | default            |
//! |--------------------|----------------|-------------------------|--------------------|
//! | config file        | `--config`          | `FEEDSIGN_CONFIG`           | `feed-config.json` |
//! | output directory   | `--out`             | `FEEDSIGN_OUT`              | `feed-out`         |
//! | transparency dir   | `--transparency-out`| `FEEDSIGN_TRANSPARENCY_OUT` | (optional)         |
//! | generated unix ts  | `--generated`       | `FEEDSIGN_GENERATED`        | (required)         |
//! | signing key (PEM/…)| —                   | `BEACON_SIGNING_KEY`        | (required)         |
//! | GitHub token       | —                   | `GITHUB_TOKEN`              | (optional)         |
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
    assert_pinned_root, produce_feed, signing_key_from_secret, FeedConfig, FeedsignError,
    GithubSource,
};

fn main() -> ExitCode {
    match run() {
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

/// The whole signing pass; returns the secret-free summary on success.
fn run() -> Result<String, FeedsignError> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let config_path = input(&args, "--config", "FEEDSIGN_CONFIG")
        .unwrap_or_else(|| "feed-config.json".to_string());
    let out_dir = input(&args, "--out", "FEEDSIGN_OUT").unwrap_or_else(|| "feed-out".to_string());
    let generated = input(&args, "--generated", "FEEDSIGN_GENERATED")
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

    let feed = produce_feed(&config, &source, generated, &signing_key)?;
    feed.write_to(std::path::Path::new(&out_dir))?;

    // Optionally emit the transparency-log triple for a public log (Rekor, #533). Derived from the
    // signed feed, so it can only reflect exactly what was published.
    if let Some(dir) = input(&args, "--transparency-out", "FEEDSIGN_TRANSPARENCY_OUT") {
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
