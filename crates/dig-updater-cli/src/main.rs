#![forbid(unsafe_code)]

//! The `dig-updater` beacon CLI (scaffold stub).
//!
//! Manual invocation surface for the beacon. In the scaffold the commands are wired but
//! return a machine-readable "not yet implemented" result — the verify/install pipeline
//! (#504-D…F) fills them in. Both a human line and a `--json` object are offered so the
//! CLI is agent-consumable from day one (§6.2).

use std::process::ExitCode;

const USAGE: &str = "\
dig-updater — DIG auto-update beacon

USAGE:
    dig-updater <COMMAND> [--json]

COMMANDS:
    check      Run one update pass now (fetch + verify + install). Use --now to force.
    status     Report the beacon's current trust state and last pass.
    help       Show this help.

OPTIONS:
    --json     Emit machine-readable JSON instead of a human line.
    --version  Print the beacon version.

NOTE: this is the alpha scaffold — check/status are wired but the verify/install/scheduler
pipeline is not yet implemented (tracked as #504-D through #504-F).";

/// Parse the argument list (excluding argv[0]) and produce the output to print.
///
/// Returns `Ok(stdout)` for a recognized command and `Err(stderr)` for an unknown one.
fn dispatch(args: &[String]) -> Result<String, String> {
    let json = args.iter().any(|a| a == "--json");
    match args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
    {
        None => Ok(USAGE.to_string()),
        Some("help") => Ok(USAGE.to_string()),
        Some("check") => Ok(render(
            json,
            "check",
            "the fetch/verify/install pipeline lands in #504-D through #504-F",
        )),
        Some("status") => Ok(render(
            json,
            "status",
            "beacon status reporting lands with the scheduler (#504-F)",
        )),
        Some(other) => Err(format!("unknown command: {other}\n\n{USAGE}")),
    }
}

/// Render a stub result either as a human line or, with `--json`, a stable JSON object.
fn render(json: bool, command: &str, detail: &str) -> String {
    if json {
        serde_json::json!({
            "command": command,
            "implemented": false,
            "status": "not-yet-implemented",
            "detail": detail,
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string()
    } else {
        format!("dig-updater {command}: not yet implemented — {detail}")
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // --version short-circuits (kept out of dispatch so the version literal has one home).
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("dig-updater {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match dispatch(&args) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_args_prints_usage() {
        assert!(dispatch(&[]).unwrap().contains("USAGE:"));
    }

    #[test]
    fn help_prints_usage() {
        assert!(dispatch(&v(&["help"])).unwrap().contains("COMMANDS:"));
    }

    #[test]
    fn check_reports_unimplemented_human() {
        let out = dispatch(&v(&["check", "--now"])).unwrap();
        assert!(out.contains("check"));
        assert!(out.contains("not yet implemented"));
    }

    #[test]
    fn status_json_is_machine_readable() {
        let out = dispatch(&v(&["status", "--json"])).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(parsed["command"], "status");
        assert_eq!(parsed["implemented"], false);
        assert_eq!(parsed["status"], "not-yet-implemented");
        assert!(parsed["detail"].is_string());
        assert!(parsed["version"].is_string());
    }

    #[test]
    fn check_json_is_machine_readable() {
        let out = dispatch(&v(&["check", "--json"])).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["command"], "check");
    }

    #[test]
    fn unknown_command_errors() {
        let err = dispatch(&v(&["frobnicate"])).unwrap_err();
        assert!(err.contains("unknown command: frobnicate"));
    }

    #[test]
    fn options_before_command_still_parse() {
        // A leading --json must not be mistaken for the command.
        let out = dispatch(&v(&["--json", "status"])).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["command"], "status");
    }
}
