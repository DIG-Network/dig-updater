#![forbid(unsafe_code)]

//! The `dig-updater` beacon CLI.
//!
//! Manual entry point to the beacon. In this (-D) milestone the wired command is
//! `check --dry-run`: it runs one privileged pass that loads the trust state, spawns the
//! unprivileged worker to fetch + verify + stage, and prints the verification report — WITHOUT
//! installing anything and WITHOUT advancing the trust state (the install path is #504-E). Both a
//! human line and a `--json` object are offered so the CLI is agent-consumable from day one
//! (§6.2).
//!
//! The feed location can be overridden for a custom/test feed via `--feed-base <url>` or
//! `$DIG_UPDATER_FEED_BASE` (transport is untrusted — the signature is the gate — so this is
//! safe). The trusted root KEY has no such override.

use std::process::ExitCode;

use dig_updater_broker::{Broker, BrokerError, TrustStateStore};
use dig_updater_trust::TrustState;
use dig_updater_worker::{production_feed_ladder, FeedSource, WorkerReport};

const USAGE: &str = "\
dig-updater — DIG auto-update beacon

USAGE:
    dig-updater <COMMAND> [OPTIONS]

COMMANDS:
    check      Fetch + verify the latest feed. In this build `check` is a DRY verify pass
               (no install, no state change); the install path lands in #504-E.
    status     Report the beacon's persisted trust state.
    help       Show this help.

OPTIONS:
    --dry-run           Verify only; never install or advance trust state (the default today).
    --now               Run the pass immediately (the manual default).
    --feed-base <url>   Override the feed base URL (for a custom/test feed). Untrusted transport.
    --json              Emit machine-readable JSON instead of a human line.
    --version, -V       Print the beacon version.";

/// The parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    Check {
        feed_base: Option<String>,
        json: bool,
    },
    Status {
        json: bool,
    },
    Help,
    Version,
    Unknown(String),
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Cmd::Version => {
            println!("dig-updater {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Cmd::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Cmd::Unknown(cmd) => {
            eprintln!("unknown command: {cmd}\n\n{USAGE}");
            ExitCode::from(2)
        }
        Cmd::Status { json } => run_status(json),
        Cmd::Check { feed_base, json } => run_check(feed_base, json),
    }
}

/// Parse argv (excluding argv[0]) into a [`Cmd`]. Pure and total — every input maps to a variant.
fn parse(args: &[String]) -> Cmd {
    if args.iter().any(|a| a == "--version" || a == "-V") {
        return Cmd::Version;
    }
    let json = args.iter().any(|a| a == "--json");
    let feed_base = flag_value(args, "--feed-base");
    match args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
    {
        None | Some("help") => Cmd::Help,
        Some("check") => Cmd::Check { feed_base, json },
        Some("status") => Cmd::Status { json },
        Some(other) => Cmd::Unknown(other.to_string()),
    }
}

/// The value following a `--flag <value>` option, if present.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Resolve the feed ladder: an explicit override (flag) wins; else `$DIG_UPDATER_FEED_BASE`; else
/// the production ladder. Only the feed URL is overridable — never the trusted key.
fn resolve_feed(feed_base: Option<String>) -> Vec<FeedSource> {
    let override_base = feed_base.or_else(|| std::env::var("DIG_UPDATER_FEED_BASE").ok());
    match override_base {
        Some(base) => vec![FeedSource::new(base)],
        None => production_feed_ladder(),
    }
}

/// Run a dry verification pass and print the report.
fn run_check(feed_base: Option<String>, json: bool) -> ExitCode {
    let broker = match Broker::new() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    match broker.dry_check(resolve_feed(feed_base)) {
        Ok(report) => {
            println!("{}", render_report(&report, json));
            match report {
                WorkerReport::Verified(_) => ExitCode::SUCCESS,
                WorkerReport::Rejected { .. } => ExitCode::from(2),
            }
        }
        Err(e) => fail(&e, json),
    }
}

/// Print the beacon's persisted trust state.
fn run_status(json: bool) -> ExitCode {
    let broker = match Broker::new() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    let store = TrustStateStore::at(broker.state_dir());
    match store.load() {
        Ok(loaded) => {
            println!(
                "{}",
                render_status(&loaded.state, &store.path().display().to_string(), json)
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e, json),
    }
}

/// Render a verification report as JSON or a human summary. Pure, so it is unit-testable.
fn render_report(report: &WorkerReport, json: bool) -> String {
    if json {
        // The report is already a stable tagged object; emit it verbatim.
        return serde_json::to_string(report)
            .unwrap_or_else(|e| format!(r#"{{"status":"error","detail":"{e}"}}"#));
    }
    match report {
        WorkerReport::Verified(plan) => {
            let mut out = format!(
                "verified feed from {} (sequence {}, {} artifact(s) staged):",
                plan.source,
                plan.sequence,
                plan.artifacts.len()
            );
            for a in &plan.artifacts {
                out.push_str(&format!(
                    "\n  {} {} [{}-{}] -> {}",
                    a.component, a.version, a.os, a.arch, a.staged_path
                ));
            }
            out
        }
        WorkerReport::Rejected { reason, detail } => format!("rejected ({reason}): {detail}"),
    }
}

/// Render the persisted trust state as JSON or a human line. Pure.
fn render_status(state: &TrustState, state_path: &str, json: bool) -> String {
    if json {
        serde_json::json!({
            "command": "status",
            "trust_state": state,
            "state_path": state_path,
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string()
    } else {
        format!(
            "dig-updater {} — trust state: root_version={} sequence={} generated={} rollback_floor_build={}",
            env!("CARGO_PKG_VERSION"),
            state.root_version,
            state.sequence,
            state.generated,
            state.rollback_floor_build,
        )
    }
}

/// Report a broker error and return a non-zero exit code.
fn fail(err: &BrokerError, json: bool) -> ExitCode {
    if json {
        let out = serde_json::json!({ "status": "error", "detail": err.to_string() });
        println!("{out}");
    } else {
        eprintln!("dig-updater: {err}");
    }
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn no_args_is_help() {
        assert_eq!(parse(&[]), Cmd::Help);
        assert_eq!(parse(&v(&["help"])), Cmd::Help);
    }

    #[test]
    fn version_flag_short_circuits() {
        assert_eq!(parse(&v(&["-V"])), Cmd::Version);
        assert_eq!(parse(&v(&["check", "--version"])), Cmd::Version);
    }

    #[test]
    fn check_parses_flags() {
        assert_eq!(
            parse(&v(&["check", "--dry-run", "--json"])),
            Cmd::Check {
                feed_base: None,
                json: true
            }
        );
    }

    #[test]
    fn check_parses_feed_base_override() {
        assert_eq!(
            parse(&v(&["check", "--feed-base", "http://localhost:8080/feed"])),
            Cmd::Check {
                feed_base: Some("http://localhost:8080/feed".to_string()),
                json: false
            }
        );
    }

    #[test]
    fn leading_option_is_not_mistaken_for_command() {
        assert_eq!(parse(&v(&["--json", "status"])), Cmd::Status { json: true });
    }

    #[test]
    fn unknown_command_is_reported() {
        assert_eq!(
            parse(&v(&["frobnicate"])),
            Cmd::Unknown("frobnicate".to_string())
        );
    }

    #[test]
    fn feed_override_flag_beats_production_ladder() {
        let sources = resolve_feed(Some("http://x/feed".to_string()));
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].base, "http://x/feed");
    }

    #[test]
    fn no_override_uses_production_ladder() {
        // Ensure the env override is not set for this assertion.
        std::env::remove_var("DIG_UPDATER_FEED_BASE");
        let sources = resolve_feed(None);
        assert_eq!(sources.len(), 2);
    }

    fn verified_report() -> WorkerReport {
        use dig_updater_worker::{StagedArtifact, VerifiedPlan};
        WorkerReport::Verified(VerifiedPlan {
            source: "https://updates.dig.net/v1/alpha".into(),
            schema: 1,
            root_version: 1,
            sequence: 42,
            generated: 1000,
            rollback_floor_build: 20,
            delegation_json: "{}".into(),
            manifest_json: "{}".into(),
            artifacts: vec![StagedArtifact {
                component: "dig-node".into(),
                version: "0.26.0".into(),
                build: 26,
                os: "linux".into(),
                arch: "x64".into(),
                sha256: "ab".into(),
                size: 10,
                staged_path: "/tmp/staging/dig-node".into(),
            }],
        })
    }

    #[test]
    fn render_verified_report_human_lists_artifacts() {
        let out = render_report(&verified_report(), false);
        assert!(out.contains("verified feed"));
        assert!(out.contains("sequence 42"));
        assert!(out.contains("dig-node 0.26.0 [linux-x64]"));
    }

    #[test]
    fn render_verified_report_json_is_machine_readable() {
        let out = render_report(&verified_report(), true);
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(parsed["status"], "verified");
        assert_eq!(parsed["sequence"], 42);
    }

    #[test]
    fn render_rejected_report_shows_reason() {
        let report = WorkerReport::Rejected {
            reason: "manifest_expired".into(),
            detail: "expired at 1, now 2".into(),
        };
        assert!(render_report(&report, false).contains("rejected (manifest_expired)"));
        let json: serde_json::Value = serde_json::from_str(&render_report(&report, true)).unwrap();
        assert_eq!(json["reason"], "manifest_expired");
    }

    #[test]
    fn render_status_human_and_json() {
        let state = TrustState {
            root_version: 1,
            sequence: 7,
            generated: 100,
            rollback_floor_build: 3,
        };
        assert!(
            render_status(&state, "/var/lib/dig-updater/trust-state.json", false)
                .contains("sequence=7")
        );
        let json: serde_json::Value =
            serde_json::from_str(&render_status(&state, "/x", true)).unwrap();
        assert_eq!(json["command"], "status");
        assert_eq!(json["trust_state"]["sequence"], 7);
    }
}
