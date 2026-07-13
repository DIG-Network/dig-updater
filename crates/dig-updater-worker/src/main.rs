#![forbid(unsafe_code)]

//! The `dig-updater-worker` binary — the UNPRIVILEGED, network-facing half of a beacon pass.
//!
//! The privileged broker spawns this process with dropped privileges, pipes a
//! [`WorkerRequest`] as JSON on **stdin**, and reads a [`WorkerReport`] as JSON on **stdout**.
//! Diagnostics go to stderr; stdout carries exactly one JSON object so the broker can parse it
//! unambiguously.
//!
//! This binary — and ONLY this binary — pins the trusted root key
//! ([`beacon_root_verifying_key`]). There is no command-line flag, environment variable, or
//! request field that can substitute a different key: the trust anchor is fixed at compile time.
//!
//! The worker never installs anything. Its entire authority is "read the network, verify, write
//! verified bytes to the staging directory it was given, and report".

use std::io::Read;
use std::process::ExitCode;

use dig_updater_trust::beacon_root_verifying_key;
use dig_updater_worker::{run, WorkerReport, WorkerRequest};

/// Exit code when the pass verified cleanly.
const EXIT_OK: u8 = 0;
/// Exit code for a hard rejection (bad signature, expired, digest mismatch, oversize, …).
const EXIT_REJECTED: u8 = 2;
/// Exit code for a transient failure (feed unreachable) worth retrying next pass.
const EXIT_TRANSIENT: u8 = 3;
/// Exit code when the request itself could not be read/parsed.
const EXIT_BAD_REQUEST: u8 = 4;

fn main() -> ExitCode {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("dig-updater-worker: could not read request from stdin: {e}");
        return ExitCode::from(EXIT_BAD_REQUEST);
    }
    let request: WorkerRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dig-updater-worker: malformed WorkerRequest: {e}");
            return ExitCode::from(EXIT_BAD_REQUEST);
        }
    };

    // THE pinned root key — the only trust anchor, fixed at compile time.
    let root = beacon_root_verifying_key();

    match run(&request, &root) {
        Ok(plan) => {
            emit(&plan.into_report());
            ExitCode::from(EXIT_OK)
        }
        Err(err) => {
            emit(&WorkerReport::rejected(&err));
            ExitCode::from(if err.is_transient() {
                EXIT_TRANSIENT
            } else {
                EXIT_REJECTED
            })
        }
    }
}

/// Print the report as a single line of JSON on stdout for the broker to parse.
fn emit(report: &WorkerReport) {
    match serde_json::to_string(report) {
        Ok(json) => println!("{json}"),
        // Serializing our own report cannot realistically fail; if it somehow does, say so on
        // stderr rather than emitting malformed stdout.
        Err(e) => eprintln!("dig-updater-worker: could not serialize report: {e}"),
    }
}
