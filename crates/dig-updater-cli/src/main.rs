#![forbid(unsafe_code)]

//! The `dig-updater` beacon CLI.
//!
//! Manual + scheduled entry point to the beacon:
//!
//! - `check` — a DRY verify pass: fetch + verify the latest feed, but never install or advance
//!   trust state. For inspecting what the beacon WOULD do.
//! - `run` — a FULL pass ([`Broker::run_once`]): verify, install behind the health gate, and
//!   (always last) the beacon's own self-update. This is the command the per-OS scheduler
//!   artifact ([`dig_updater_broker::scheduler`]) invokes daily.
//! - `schedule install|uninstall|status` — register/remove/report the daily scheduler artifact
//!   that invokes `run` (SPEC §8.2, #504-F). Registering requires the privilege the artifact
//!   itself runs at (Administrator on Windows, root on Unix).
//! - `status` — report the beacon's persisted trust state.
//!
//! Every command offers a human line AND a `--json` object so the CLI is agent-consumable from
//! day one (§6.2). The feed location can be overridden for a custom/test feed via
//! `--feed-base <url>` or `$DIG_UPDATER_FEED_BASE` (transport is untrusted — the signature is the
//! gate — so this is safe); the trusted root KEY has no such override.

use std::path::PathBuf;
use std::process::ExitCode;

use dig_updater_broker::{scheduler, Broker, BrokerError, PassReport, TrustStateStore};
use dig_updater_trust::TrustState;
use dig_updater_worker::{production_feed_ladder, FeedSource, WorkerReport};

const USAGE: &str = "\
dig-updater — DIG auto-update beacon

USAGE:
    dig-updater <COMMAND> [OPTIONS]

COMMANDS:
    check                Fetch + verify the latest feed — a DRY pass: no install, no state change.
    run                  Run one FULL pass: verify, install behind the health gate, and
                         self-update. This is what the daily schedule invokes.
    schedule install     Register the daily scheduler artifact that runs `dig-updater run`
                         (requires Administrator/root).
    schedule uninstall   Remove the daily scheduler artifact (requires Administrator/root).
    schedule status      Report whether the daily scheduler artifact is registered.
    status               Report the beacon's persisted trust state.
    help                 Show this help.

OPTIONS:
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
    Run {
        json: bool,
    },
    Schedule {
        action: ScheduleAction,
        json: bool,
    },
    Status {
        json: bool,
    },
    Help,
    Version,
    Unknown(String),
}

/// Which `schedule` subcommand was requested.
#[derive(Debug, PartialEq, Eq)]
enum ScheduleAction {
    Install,
    Uninstall,
    Status,
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
        Cmd::Run { json } => run_pass(json),
        Cmd::Schedule { action, json } => run_schedule(action, json),
    }
}

/// Parse argv (excluding argv[0]) into a [`Cmd`]. Pure and total — every input maps to a variant.
fn parse(args: &[String]) -> Cmd {
    if args.iter().any(|a| a == "--version" || a == "-V") {
        return Cmd::Version;
    }
    let json = args.iter().any(|a| a == "--json");
    let feed_base = flag_value(args, "--feed-base");
    let positionals: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    match positionals.first().copied() {
        None | Some("help") => Cmd::Help,
        Some("check") => Cmd::Check { feed_base, json },
        Some("run") => Cmd::Run { json },
        Some("status") => Cmd::Status { json },
        Some("schedule") => Cmd::Schedule {
            action: parse_schedule_action(positionals.get(1).copied()),
            json,
        },
        Some(other) => Cmd::Unknown(other.to_string()),
    }
}

/// Parse the sub-action of `schedule <action>`.
fn parse_schedule_action(action: Option<&str>) -> ScheduleAction {
    match action {
        Some("install") => ScheduleAction::Install,
        Some("uninstall") => ScheduleAction::Uninstall,
        Some("status") => ScheduleAction::Status,
        Some(other) => ScheduleAction::Unknown(other.to_string()),
        None => ScheduleAction::Unknown(String::new()),
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

/// Run one FULL update pass — [`Broker::run_once`] — and print the report. This is the command
/// the daily scheduler artifact invokes; a manual run behaves identically.
fn run_pass(json: bool) -> ExitCode {
    let broker = match Broker::new() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    match broker.run_once() {
        Ok(report) => {
            println!("{}", render_pass_report(&report, json));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e, json),
    }
}

/// Register, remove, or report the daily scheduler artifact that runs `dig-updater run`.
fn run_schedule(action: ScheduleAction, json: bool) -> ExitCode {
    let exe = match current_exe_for_schedule() {
        Ok(p) => p,
        Err(e) => return fail(&e, json),
    };
    match action {
        ScheduleAction::Install => match scheduler::install(&exe) {
            Ok(()) => {
                print_schedule_outcome("installed", true, json);
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e, json),
        },
        ScheduleAction::Uninstall => match scheduler::uninstall() {
            Ok(()) => {
                print_schedule_outcome("uninstalled", false, json);
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e, json),
        },
        ScheduleAction::Status => match scheduler::status() {
            Ok(status) => {
                println!("{}", render_schedule_status(&status, json));
                if status.installed {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(e) => fail(&e, json),
        },
        ScheduleAction::Unknown(action) => {
            eprintln!("unknown schedule action: {action}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// The executable path the scheduler artifact should invoke — this running binary itself.
fn current_exe_for_schedule() -> Result<PathBuf, BrokerError> {
    std::env::current_exe().map_err(|e| BrokerError::Io(e.to_string()))
}

/// Print a one-line confirmation for `schedule install`/`uninstall`.
fn print_schedule_outcome(verb: &str, installed: bool, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({ "command": "schedule", "installed": installed })
        );
    } else {
        println!("dig-updater: daily schedule {verb}");
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

/// Render a FULL pass's report ([`Broker::run_once`]) as JSON or a human summary. Pure.
fn render_pass_report(report: &PassReport, json: bool) -> String {
    if json {
        return serde_json::to_string(report)
            .unwrap_or_else(|e| format!(r#"{{"status":"error","detail":"{e}"}}"#));
    }
    if !report.applied {
        let reason = report.reason.as_deref().unwrap_or("unknown");
        let detail = report.detail.as_deref().unwrap_or("");
        return format!("nothing applied ({reason}): {detail}");
    }
    let mut out = format!(
        "pass applied ({} component(s), trust state {}advanced):",
        report.components.len(),
        if report.state_advanced { "" } else { "NOT " }
    );
    for c in &report.components {
        out.push_str(&format!(
            "\n  {} [{}] {:?}: {}",
            c.component, c.action, c.result, c.detail
        ));
    }
    out
}

/// Render the scheduler artifact's registration status as JSON or a human line. Pure.
fn render_schedule_status(status: &scheduler::ScheduleStatus, json: bool) -> String {
    if json {
        serde_json::json!({
            "command": "schedule status",
            "installed": status.installed,
            "detail": status.detail,
        })
        .to_string()
    } else {
        format!(
            "dig-updater: daily schedule {} — {}",
            if status.installed {
                "REGISTERED"
            } else {
                "NOT REGISTERED"
            },
            status.detail
        )
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
            parse(&v(&["check", "--json"])),
            Cmd::Check {
                feed_base: None,
                json: true
            }
        );
    }

    #[test]
    fn run_parses_json_flag() {
        assert_eq!(parse(&v(&["run"])), Cmd::Run { json: false });
        assert_eq!(parse(&v(&["run", "--json"])), Cmd::Run { json: true });
    }

    #[test]
    fn schedule_parses_each_action() {
        assert_eq!(
            parse(&v(&["schedule", "install"])),
            Cmd::Schedule {
                action: ScheduleAction::Install,
                json: false
            }
        );
        assert_eq!(
            parse(&v(&["schedule", "uninstall", "--json"])),
            Cmd::Schedule {
                action: ScheduleAction::Uninstall,
                json: true
            }
        );
        assert_eq!(
            parse(&v(&["schedule", "status"])),
            Cmd::Schedule {
                action: ScheduleAction::Status,
                json: false
            }
        );
    }

    #[test]
    fn schedule_with_no_or_unknown_action_is_reported() {
        assert_eq!(
            parse(&v(&["schedule"])),
            Cmd::Schedule {
                action: ScheduleAction::Unknown(String::new()),
                json: false
            }
        );
        assert_eq!(
            parse(&v(&["schedule", "frobnicate"])),
            Cmd::Schedule {
                action: ScheduleAction::Unknown("frobnicate".to_string()),
                json: false
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

    fn applied_report() -> PassReport {
        use dig_updater_broker::{ComponentOutcome, ComponentResult};
        PassReport {
            applied: true,
            reason: None,
            detail: None,
            components: vec![
                ComponentOutcome {
                    component: "digstore".into(),
                    action: "update".into(),
                    result: ComponentResult::Installed,
                    detail: "v0.1.0 -> v0.2.0".into(),
                },
                ComponentOutcome {
                    component: "dig-updater".into(),
                    action: "skip".into(),
                    result: ComponentResult::Skipped,
                    detail: "already current".into(),
                },
            ],
            state_advanced: true,
        }
    }

    #[test]
    fn render_applied_pass_report_human_lists_components_in_order() {
        let out = render_pass_report(&applied_report(), false);
        assert!(out.contains("2 component(s)"));
        assert!(out.contains("trust state advanced"));
        let digstore_at = out.find("digstore").expect("digstore listed");
        let updater_at = out.find("dig-updater").expect("dig-updater listed");
        assert!(
            digstore_at < updater_at,
            "digstore must be listed before the beacon's own component"
        );
    }

    #[test]
    fn render_applied_pass_report_json_round_trips_the_report() {
        let out = render_pass_report(&applied_report(), true);
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(parsed["applied"], true);
        assert_eq!(parsed["state_advanced"], true);
        assert_eq!(parsed["components"][0]["component"], "digstore");
    }

    #[test]
    fn render_already_running_pass_report_is_a_benign_nothing_applied() {
        let out = render_pass_report(&PassReport::already_running(), false);
        assert!(out.contains("nothing applied"));
        assert!(out.contains("already_running"));
    }

    #[test]
    fn render_schedule_status_human_and_json() {
        let installed = scheduler::ScheduleStatus {
            installed: true,
            detail: r"registered at \DIG\dig-updater".into(),
        };
        assert!(render_schedule_status(&installed, false).contains("REGISTERED"));
        let json: serde_json::Value =
            serde_json::from_str(&render_schedule_status(&installed, true)).unwrap();
        assert_eq!(json["installed"], true);

        let absent = scheduler::ScheduleStatus {
            installed: false,
            detail: "no task registered".into(),
        };
        assert!(render_schedule_status(&absent, false).contains("NOT REGISTERED"));
    }
}
