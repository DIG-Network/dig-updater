#![forbid(unsafe_code)]

//! The `dig-updater` beacon CLI — the operator interface over the beacon engine (SPEC §12/§13).
//!
//! Manual + scheduled entry point to the beacon:
//!
//! - `check [--now|--dry-run]` — `--now` triggers a REAL pass immediately (an on-demand
//!   [`Broker::run_once_with_feed`] — the same gating a scheduled wake gets); the default (and
//!   `--dry-run`) stays a DRY verify: fetch + verify the latest feed, but never install or
//!   advance trust state. For inspecting what the beacon WOULD do.
//! - `run` — a FULL pass ([`Broker::run_once`]): verify, install behind the health gate, and
//!   (always last) the beacon's own self-update. This is the command the per-OS scheduler
//!   artifact ([`dig_updater_broker::scheduler`]) invokes daily.
//! - `channel get|set <nightly|stable>` — read or set the update channel (SPEC §13.1); the channel
//!   selects which signed feed the beacon fetches and which per-channel anti-rollback state it
//!   advances. `get` never needs elevation (it reads the unprivileged status mirror); `set` does
//!   (it writes `config.json`). The legacy `alpha` token is accepted as an alias for `nightly`.
//! - `pause [--until <unix-ts>]` / `resume` — suspend/resume auto-updates (SPEC §13.1); a paused
//!   beacon's next `run`/`check --now` no-ops instead of acting. Requires elevation.
//! - `schedule install|uninstall|status` — register/remove/report the daily scheduler artifact
//!   that invokes `run` (SPEC §8.2, #504-F). Registering requires the privilege the artifact
//!   itself runs at (Administrator on Windows, root on Unix).
//! - `status` — the beacon's UNPRIVILEGED status mirror (SPEC §13.2): last check, per-component
//!   decisions, channel, paused state, next wake, and a read-only copy of the trust marks. Never
//!   requires elevation — distinct from the Admin-only trust/config state `channel set`/`pause`
//!   write.
//!
//! Every command offers a human line AND a `--json` object so the CLI is agent-consumable from
//! day one (§6.2). The feed location can be overridden for a custom/test feed via
//! `--feed-base <url>` or `$DIG_UPDATER_FEED_BASE` (transport is untrusted — the signature is the
//! gate — so this is safe); the trusted root KEY has no such override.

use std::path::PathBuf;
use std::process::ExitCode;

use dig_updater_broker::config::{Channel, UpdaterConfig};
use dig_updater_broker::status::StatusSnapshot;
use dig_updater_broker::{elevation, scheduler, Broker, BrokerError, PassReport};
use dig_updater_worker::{FeedSource, WorkerReport};

const USAGE: &str = "\
dig-updater — DIG auto-update beacon

USAGE:
    dig-updater <COMMAND> [OPTIONS]

COMMANDS:
    check                Fetch + verify the latest feed — a DRY pass: no install, no state change.
    check --now          Run a REAL pass immediately (an on-demand `run`) instead of a dry verify.
    run                  Run one FULL pass: verify, install behind the health gate, and
                         self-update. This is what the daily schedule invokes.
    channel get          Print the currently configured update channel.
    channel set <chan>   Set the update channel to `nightly` or `stable` (requires
                         Administrator/root). `alpha` is accepted as an alias for `nightly`.
    pause [--until <ts>] Suspend auto-updates, optionally until a unix-seconds deadline
                         (requires Administrator/root).
    resume               Resume auto-updates (requires Administrator/root).
    schedule install     Register the daily scheduler artifact that runs `dig-updater run`
                         (requires Administrator/root).
    schedule uninstall   Remove the daily scheduler artifact (requires Administrator/root).
    schedule status      Report whether the daily scheduler artifact is registered.
    status               Report the beacon's unprivileged status mirror — no elevation required.
    help                 Show this help.

OPTIONS:
    --now               With `check`: run a real pass instead of a dry verify.
    --dry-run           With `check`: stay a dry verify (the default — explicit alias).
    --until <unix-ts>   With `pause`: an optional snooze deadline (unix seconds).
    --feed-base <url>   With `check`/`run`: override the feed base URL (for a custom/test feed).
                        Untrusted transport.
    --json              Emit machine-readable JSON instead of a human line.
    --version, -V       Print the beacon version.";

/// The parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    Check {
        mode: CheckMode,
        feed_base: Option<String>,
        json: bool,
    },
    Run {
        feed_base: Option<String>,
        json: bool,
    },
    Channel {
        action: ChannelAction,
        json: bool,
    },
    Pause {
        until: Option<String>,
        json: bool,
    },
    Resume {
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

/// Whether `check` performs a dry verify or triggers a real pass on demand.
#[derive(Debug, PartialEq, Eq)]
enum CheckMode {
    /// The default: fetch + verify, never install or advance state.
    Dry,
    /// `--now`: an on-demand real pass — identical gating to a scheduled `run`.
    Now,
}

/// Which `channel` subcommand was requested.
#[derive(Debug, PartialEq, Eq)]
enum ChannelAction {
    Get,
    /// The raw token (e.g. `"nightly"`), validated against the known channels at execution time —
    /// keeping `parse` itself total and side-effect-free.
    Set(String),
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
        Cmd::Check {
            mode,
            feed_base,
            json,
        } => match mode {
            CheckMode::Dry => run_dry_check(feed_base, json),
            CheckMode::Now => run_pass(feed_base, json),
        },
        Cmd::Run { feed_base, json } => run_pass(feed_base, json),
        Cmd::Channel { action, json } => run_channel(action, json),
        Cmd::Pause { until, json } => run_pause(until, json),
        Cmd::Resume { json } => run_resume(json),
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
        Some("check") => Cmd::Check {
            mode: if args.iter().any(|a| a == "--now") {
                CheckMode::Now
            } else {
                CheckMode::Dry
            },
            feed_base,
            json,
        },
        Some("run") => Cmd::Run { feed_base, json },
        Some("status") => Cmd::Status { json },
        Some("channel") => Cmd::Channel {
            action: parse_channel_action(positionals.get(1).copied(), positionals.get(2).copied()),
            json,
        },
        Some("pause") => Cmd::Pause {
            until: flag_value(args, "--until"),
            json,
        },
        Some("resume") => Cmd::Resume { json },
        Some("schedule") => Cmd::Schedule {
            action: parse_schedule_action(positionals.get(1).copied()),
            json,
        },
        Some(other) => Cmd::Unknown(other.to_string()),
    }
}

/// Parse the sub-action of `channel <action> [token]`.
fn parse_channel_action(action: Option<&str>, token: Option<&str>) -> ChannelAction {
    match (action, token) {
        (Some("get"), _) => ChannelAction::Get,
        (Some("set"), Some(token)) => ChannelAction::Set(token.to_string()),
        (Some("set"), None) => ChannelAction::Unknown("set (missing <nightly|stable>)".to_string()),
        (Some(other), _) => ChannelAction::Unknown(other.to_string()),
        (None, _) => ChannelAction::Unknown(String::new()),
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

/// Resolve an OPTIONAL feed-transport override: an explicit `--feed-base` flag wins, else
/// `$DIG_UPDATER_FEED_BASE`. `None` means "no override" — the broker then derives the ladder from
/// the tracked channel (SPEC §13.1). Only the feed URL is overridable — never the trusted key.
fn resolve_feed(feed_base: Option<String>) -> Option<Vec<FeedSource>> {
    feed_base
        .or_else(|| std::env::var("DIG_UPDATER_FEED_BASE").ok())
        .map(|base| vec![FeedSource::new(base)])
}

/// Run a DRY verification pass (`check` / `check --dry-run`) and print the report. Never installs
/// or advances trust state; also never gates on a pause ([`Broker::run_once_with_feed`] does —
/// inspecting what the beacon WOULD do stays available while paused).
fn run_dry_check(feed_base: Option<String>, json: bool) -> ExitCode {
    // `for_dry_check` (not `new`) so an UNELEVATED check relocates off the Admin/SYSTEM-owned
    // default on its own (#582), or honors an explicit `DIG_UPDATER_STATE_DIR` override — the dry
    // verify never installs, so this can't defeat anti-rollback, and it's what lets the
    // signed-feed keystone verify without Admin rights (#540).
    let broker = match Broker::for_dry_check() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    match broker.dry_check(resolve_feed(feed_base)) {
        Ok(report) => {
            println!("{}", render_report(&report, json));
            if should_print_staging_directive(&report, json) {
                eprintln!("{STAGING_IO_ERROR_DIRECTIVE}");
            }
            match report {
                WorkerReport::Verified(_) => ExitCode::SUCCESS,
                WorkerReport::Rejected { .. } => ExitCode::from(2),
            }
        }
        Err(e) => fail(&e, json),
    }
}

/// The actionable remedy printed alongside a `staging_io_error` dry-check rejection (#582): the
/// raw failure alone ("rejected (staging_io_error): ... os error 183") doesn't tell an operator
/// WHAT to do about it — the auto-relocation ([`Broker::for_dry_check`]) already handles the
/// common case, so reaching this message means even the per-user fallback location wasn't usable
/// (e.g. an explicit `DIG_UPDATER_STATE_DIR` pointed somewhere unwritable).
const STAGING_IO_ERROR_DIRECTIVE: &str = "dig-updater: the dry check could not stage the feed's \
    artifacts for verification. Try: running from an elevated (Administrator/root) console, \
    setting DIG_UPDATER_STATE_DIR to a directory you can write to, or running `dig-updater \
    status` to see the last-known state without staging anything.";

/// Whether [`STAGING_IO_ERROR_DIRECTIVE`] belongs alongside this report: only for the human
/// (non-JSON) render, and only for the specific rejection it explains. A JSON consumer already has
/// the structured `"reason": "staging_io_error"` code to branch on (§6.2) and should never have to
/// filter prose out of its parsed output.
fn should_print_staging_directive(report: &WorkerReport, json: bool) -> bool {
    !json && matches!(report, WorkerReport::Rejected { reason, .. } if reason == "staging_io_error")
}

/// Run one FULL update pass — [`Broker::run_once_with_feed`] — and print the report. This is the
/// command the daily scheduler artifact invokes (`run`); `check --now` is the identical on-demand
/// trigger. A paused beacon reports [`PassReport::paused`] rather than acting.
fn run_pass(feed_base: Option<String>, json: bool) -> ExitCode {
    let broker = match Broker::new() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    match broker.run_once_with_feed(resolve_feed(feed_base)) {
        Ok(report) => {
            println!("{}", render_pass_report(&report, json));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e, json),
    }
}

/// Get or set the update channel (SPEC §13.1). `get` reads the unprivileged status mirror; `set`
/// writes `config.json` and requires elevation.
fn run_channel(action: ChannelAction, json: bool) -> ExitCode {
    let broker = match Broker::new() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    match action {
        ChannelAction::Get => match broker.channel() {
            Ok(channel) => {
                println!("{}", render_channel(channel, json));
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e, json),
        },
        ChannelAction::Set(token) => match parse_channel_token(&token) {
            Ok(channel) => match broker.set_channel(channel, elevation::is_elevated) {
                Ok(config) => {
                    println!("{}", render_channel(config.channel, json));
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e, json),
            },
            Err(msg) => report_usage_error(&msg, json),
        },
        ChannelAction::Unknown(action) => {
            eprintln!("unknown channel action: {action}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Validate a `channel set` token against the channels the beacon tracks (SPEC §13.1). Both
/// `nightly` and `stable` are servable; the legacy `alpha` token is accepted as a hidden alias for
/// `nightly` (alpha ≡ nightly, #591 D3) so an existing caller keeps working. Anything else is a
/// clear usage error rather than a silently-ignored value.
fn parse_channel_token(token: &str) -> Result<Channel, String> {
    match token.trim().to_ascii_lowercase().as_str() {
        "nightly" | "alpha" => Ok(Channel::Nightly),
        "stable" => Ok(Channel::Stable),
        other => Err(format!(
            "unknown channel '{other}' (expected 'nightly' or 'stable')"
        )),
    }
}

/// Suspend auto-updates, optionally until a unix-seconds deadline. Requires elevation.
fn run_pause(until: Option<String>, json: bool) -> ExitCode {
    let until = match until.map(|raw| parse_unix_seconds(&raw)).transpose() {
        Ok(until) => until,
        Err(msg) => return report_usage_error(&msg, json),
    };
    let broker = match Broker::new() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    match broker.pause(until, elevation::is_elevated) {
        Ok(config) => {
            println!("{}", render_pause_outcome(&config, json));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e, json),
    }
}

/// Resume auto-updates (clears any pause). Requires elevation.
fn run_resume(json: bool) -> ExitCode {
    let broker = match Broker::new() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    match broker.resume(elevation::is_elevated) {
        Ok(config) => {
            println!("{}", render_pause_outcome(&config, json));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e, json),
    }
}

/// Parse a `--until` value as unix seconds, with a clear message on a malformed argument.
fn parse_unix_seconds(raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|_| format!("--until expects unix seconds, got '{raw}'"))
}

/// Report a command-line USAGE error (a bad argument value, as opposed to a [`BrokerError`]) and
/// return the same non-zero exit code every other failure path uses.
fn report_usage_error(message: &str, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::json!({ "status": "error", "detail": message })
        );
    } else {
        eprintln!("dig-updater: {message}");
    }
    ExitCode::from(2)
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
                if status.installed() {
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

/// Print the beacon's UNPRIVILEGED status mirror (SPEC §13.2) — no elevation required, distinct
/// from the Admin-only trust/config state `channel set`/`pause`/`resume` write.
fn run_status(json: bool) -> ExitCode {
    let broker = match Broker::new() {
        Ok(b) => b,
        Err(e) => return fail(&e, json),
    };
    match broker.status() {
        Ok(status) => {
            println!("{}", render_status(&status, json));
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
///
/// Three states, honestly distinct (#546): REGISTERED, NOT REGISTERED (provably absent), and
/// UNKNOWN (the presence couldn't be read — e.g. an unprivileged query against the SYSTEM task).
/// UNKNOWN is deliberately NOT reported as NOT REGISTERED, which would have been a lie.
fn render_schedule_status(status: &scheduler::ScheduleStatus, json: bool) -> String {
    if json {
        serde_json::json!({
            "command": "schedule status",
            "installed": status.installed(),
            "detail": status.detail,
        })
        .to_string()
    } else {
        let label = match status.presence {
            scheduler::SchedulePresence::Registered => "REGISTERED",
            scheduler::SchedulePresence::Absent => "NOT REGISTERED",
            scheduler::SchedulePresence::Unknown => "UNKNOWN",
        };
        format!("dig-updater: daily schedule {label} — {}", status.detail)
    }
}

/// Render the beacon's unprivileged status mirror (SPEC §13.2) as JSON or a human summary. Pure.
fn render_status(status: &StatusSnapshot, json: bool) -> String {
    if json {
        // Already a stable, schema-versioned object (SPEC §13.2) — emit it verbatim.
        return serde_json::to_string(status)
            .unwrap_or_else(|e| format!(r#"{{"status":"error","detail":"{e}"}}"#));
    }
    let last_check = match (
        status.last_check,
        &status.last_check_kind,
        &status.last_outcome,
    ) {
        (Some(at), Some(kind), Some(outcome)) => format!("{kind} check at {at} -> {outcome}"),
        _ => "never checked".to_string(),
    };
    let mut out = format!(
        "dig-updater {} — channel={} paused={} — last check: {last_check}",
        status.version, status.channel, status.paused
    );
    for c in &status.components {
        out.push_str(&format!(
            "\n  {} [{}] {}: {}",
            c.component, c.action, c.result, c.detail
        ));
    }
    out
}

/// Render `channel get`/`channel set`'s outcome as JSON or a human line. Pure.
fn render_channel(channel: Channel, json: bool) -> String {
    if json {
        serde_json::json!({ "command": "channel", "channel": channel.as_str() }).to_string()
    } else {
        format!("dig-updater: channel = {channel}")
    }
}

/// Render `pause`/`resume`'s resulting config as JSON or a human line. Pure.
fn render_pause_outcome(config: &UpdaterConfig, json: bool) -> String {
    if json {
        serde_json::json!({
            "command": "pause",
            "paused": config.paused,
            "paused_until": config.paused_until,
        })
        .to_string()
    } else if config.paused {
        match config.paused_until {
            Some(until) => format!("dig-updater: auto-updates paused until unix time {until}"),
            None => "dig-updater: auto-updates paused".to_string(),
        }
    } else {
        "dig-updater: auto-updates resumed".to_string()
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
                mode: CheckMode::Dry,
                feed_base: None,
                json: true
            }
        );
    }

    #[test]
    fn check_dry_run_is_an_explicit_alias_for_the_default() {
        assert_eq!(
            parse(&v(&["check", "--dry-run"])),
            Cmd::Check {
                mode: CheckMode::Dry,
                feed_base: None,
                json: false
            }
        );
    }

    #[test]
    fn check_now_triggers_a_real_pass() {
        assert_eq!(
            parse(&v(&["check", "--now"])),
            Cmd::Check {
                mode: CheckMode::Now,
                feed_base: None,
                json: false
            }
        );
    }

    #[test]
    fn run_parses_json_and_feed_base_flags() {
        assert_eq!(
            parse(&v(&["run"])),
            Cmd::Run {
                feed_base: None,
                json: false
            }
        );
        assert_eq!(
            parse(&v(&["run", "--json"])),
            Cmd::Run {
                feed_base: None,
                json: true
            }
        );
        assert_eq!(
            parse(&v(&["run", "--feed-base", "http://localhost:8080/feed"])),
            Cmd::Run {
                feed_base: Some("http://localhost:8080/feed".to_string()),
                json: false
            }
        );
    }

    #[test]
    fn channel_parses_get_and_set() {
        assert_eq!(
            parse(&v(&["channel", "get"])),
            Cmd::Channel {
                action: ChannelAction::Get,
                json: false
            }
        );
        assert_eq!(
            parse(&v(&["channel", "set", "nightly"])),
            Cmd::Channel {
                action: ChannelAction::Set("nightly".to_string()),
                json: false
            }
        );
    }

    #[test]
    fn channel_set_without_a_token_is_reported_not_silently_dropped() {
        assert_eq!(
            parse(&v(&["channel", "set"])),
            Cmd::Channel {
                action: ChannelAction::Unknown("set (missing <nightly|stable>)".to_string()),
                json: false
            }
        );
    }

    #[test]
    fn pause_parses_the_until_flag() {
        assert_eq!(
            parse(&v(&["pause"])),
            Cmd::Pause {
                until: None,
                json: false
            }
        );
        assert_eq!(
            parse(&v(&["pause", "--until", "1700000000"])),
            Cmd::Pause {
                until: Some("1700000000".to_string()),
                json: false
            }
        );
    }

    #[test]
    fn resume_parses_the_json_flag() {
        assert_eq!(parse(&v(&["resume"])), Cmd::Resume { json: false });
        assert_eq!(parse(&v(&["resume", "--json"])), Cmd::Resume { json: true });
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
                mode: CheckMode::Dry,
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
    fn feed_override_flag_yields_a_single_source() {
        let sources = resolve_feed(Some("http://x/feed".to_string())).expect("an override is Some");
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].base, "http://x/feed");
    }

    #[test]
    fn no_override_defers_the_ladder_to_the_broker_channel() {
        // With no `--feed-base`/env override, `resolve_feed` returns None — the broker then derives
        // the ladder from the tracked channel (SPEC §13.1), never a hardcoded feed.
        std::env::remove_var("DIG_UPDATER_FEED_BASE");
        assert_eq!(resolve_feed(None), None);
    }

    fn verified_report() -> WorkerReport {
        use dig_updater_worker::{StagedArtifact, VerifiedPlan};
        WorkerReport::Verified(VerifiedPlan {
            source: "https://updates.dig.net/v1/nightly".into(),
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
    fn staging_directive_accompanies_only_a_human_staging_io_error_rejection() {
        // #582: a bare `staging_io_error` gets the actionable remedy — but only for a human
        // reader; a JSON consumer already has the structured reason code to branch on.
        let staging_rejected = WorkerReport::Rejected {
            reason: "staging_io_error".into(),
            detail: "os error 183".into(),
        };
        assert!(should_print_staging_directive(&staging_rejected, false));
        assert!(
            !should_print_staging_directive(&staging_rejected, true),
            "JSON output must stay parseable prose-free"
        );
    }

    #[test]
    fn staging_directive_never_accompanies_an_unrelated_rejection_or_a_verified_report() {
        let other_rejection = WorkerReport::Rejected {
            reason: "manifest_expired".into(),
            detail: "expired at 1, now 2".into(),
        };
        assert!(!should_print_staging_directive(&other_rejection, false));
        assert!(!should_print_staging_directive(&verified_report(), false));
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

    fn never_checked_status() -> StatusSnapshot {
        StatusSnapshot::never_checked()
    }

    #[test]
    fn render_status_never_checked_is_answerable_not_an_error() {
        let status = never_checked_status();
        let human = render_status(&status, false);
        assert!(human.contains("never checked"));
        assert!(human.contains("channel=stable"));
        assert!(human.contains("paused=false"));

        let json: serde_json::Value = serde_json::from_str(&render_status(&status, true)).unwrap();
        assert_eq!(json["channel"], "stable");
        assert_eq!(json["last_check"], serde_json::Value::Null);
    }

    #[test]
    fn render_status_lists_components_and_the_last_outcome() {
        let mut status = never_checked_status();
        status.last_check = Some(100);
        status.last_check_kind = Some("run".to_string());
        status.last_outcome = Some("applied".to_string());
        status
            .components
            .push(dig_updater_broker::status::ComponentStatus {
                component: "digstore".to_string(),
                action: "update".to_string(),
                result: "installed".to_string(),
                detail: "v0.1.0 -> v0.2.0".to_string(),
            });
        let human = render_status(&status, false);
        assert!(human.contains("run check at 100 -> applied"));
        assert!(human.contains("digstore [update] installed"));
    }

    #[test]
    fn render_channel_human_and_json() {
        assert_eq!(
            render_channel(Channel::Nightly, false),
            "dig-updater: channel = nightly"
        );
        let json: serde_json::Value =
            serde_json::from_str(&render_channel(Channel::Nightly, true)).unwrap();
        assert_eq!(json["channel"], "nightly");
        // Stable renders its own token too.
        let stable: serde_json::Value =
            serde_json::from_str(&render_channel(Channel::Stable, true)).unwrap();
        assert_eq!(stable["channel"], "stable");
    }

    #[test]
    fn render_pause_outcome_reports_indefinite_and_timed_and_resumed() {
        let indefinite = UpdaterConfig {
            paused: true,
            paused_until: None,
            ..UpdaterConfig::default()
        };
        let indefinite_out = render_pause_outcome(&indefinite, false);
        assert!(indefinite_out.contains("paused"));
        assert!(!indefinite_out.contains("until"));

        let timed = UpdaterConfig {
            paused: true,
            paused_until: Some(1_700_000_000),
            ..UpdaterConfig::default()
        };
        assert!(render_pause_outcome(&timed, false).contains("until unix time 1700000000"));

        let resumed = UpdaterConfig::default();
        assert!(render_pause_outcome(&resumed, false).contains("resumed"));

        let json: serde_json::Value =
            serde_json::from_str(&render_pause_outcome(&timed, true)).unwrap();
        assert_eq!(json["paused"], true);
        assert_eq!(json["paused_until"], 1_700_000_000);
    }

    #[test]
    fn parse_channel_token_accepts_nightly_stable_and_the_alpha_alias_rejects_garbage() {
        assert_eq!(parse_channel_token("nightly"), Ok(Channel::Nightly));
        assert_eq!(parse_channel_token("stable"), Ok(Channel::Stable));
        // `alpha` is a hidden back-compat alias for nightly (alpha ≡ nightly, #591 D3).
        assert_eq!(parse_channel_token("alpha"), Ok(Channel::Nightly));
        // Case/whitespace tolerant.
        assert_eq!(parse_channel_token("  STABLE "), Ok(Channel::Stable));
        // Anything else is a clear usage error, never silently accepted.
        assert!(parse_channel_token("beta").unwrap_err().contains("unknown"));
        assert!(parse_channel_token("garbage")
            .unwrap_err()
            .contains("unknown"));
    }

    #[test]
    fn parse_unix_seconds_accepts_digits_and_rejects_garbage() {
        assert_eq!(parse_unix_seconds("1700000000"), Ok(1_700_000_000));
        assert!(parse_unix_seconds("tomorrow").is_err());
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
        use scheduler::SchedulePresence;

        let installed = scheduler::ScheduleStatus {
            presence: SchedulePresence::Registered,
            detail: r"registered at \DIG\dig-updater".into(),
        };
        assert!(render_schedule_status(&installed, false).contains("REGISTERED"));
        let json: serde_json::Value =
            serde_json::from_str(&render_schedule_status(&installed, true)).unwrap();
        assert_eq!(json["installed"], true);

        let absent = scheduler::ScheduleStatus {
            presence: SchedulePresence::Absent,
            detail: "no task registered".into(),
        };
        let absent_human = render_schedule_status(&absent, false);
        assert!(absent_human.contains("NOT REGISTERED"));
        assert!(!absent_human.contains("UNKNOWN"));

        // #546: an access-denied query reads as its own UNKNOWN state, never as NOT REGISTERED.
        let unknown = scheduler::ScheduleStatus {
            presence: SchedulePresence::Unknown,
            detail: "access denied".into(),
        };
        let unknown_human = render_schedule_status(&unknown, false);
        assert!(unknown_human.contains("UNKNOWN"));
        assert!(!unknown_human.contains("NOT REGISTERED"));
        let unknown_json: serde_json::Value =
            serde_json::from_str(&render_schedule_status(&unknown, true)).unwrap();
        assert_eq!(unknown_json["installed"], false);
    }
}
