//! Detecting whether a per-user desktop component's OWN binary is currently a running process's
//! image — the one liveness signal available for a component the applier must never execute to
//! probe ([`crate::plan::VersionEvidence::ArtifactDigest`], dig_ecosystem#1803, #92).
//!
//! [`ComponentTarget::service`](crate::plan::ComponentTarget::service) is `None` for these by
//! construction (SPEC §9.7(1) — a per-user tray/GUI agent, not a machine service), so there is no
//! service handle [`crate::pass::Installer::process_probe`]'s sibling
//! [`crate::pass::Installer::service_probe`] could ask instead. The only question this module
//! answers is "is ANY process currently running whose image file is named like this component's
//! binary" — matched by FILE NAME, the same imprecision a service probe already accepts for a
//! service's registered name, because neither platform's everywhere-available tool reports a
//! process's full launch path uniformly.

use std::path::Path;
use std::process::Command;

use crate::proc::HideConsole;

/// The injectable shape of [`is_running`] — [`crate::service::ServiceProbe`]'s counterpart for a
/// component with no service handle. Production wires [`is_running`] itself; tests inject a
/// scripted answer so [`crate::pass::Installer`]'s pending-restart branch is exercised
/// deterministically, without shelling out to a real process-list tool.
pub type ProcessProbe<'a> = dyn Fn(&Path) -> bool + 'a;

/// Ask the OS process list whether `binary`'s file name is the image of any currently-running
/// process. Production wiring for [`crate::pass::Installer::process_probe`]; tests inject a
/// scripted answer so the pending-restart branch is exercised deterministically.
///
/// Best-effort and fails CLOSED (`false`, "nothing detected running") on any tool error or an
/// unnamed path — a probe that could not run must never MANUFACTURE a stale-process warning. The
/// silence this replaces (#92) is the floor this falls back to, never a regression below it.
#[must_use]
pub fn is_running(binary: &Path) -> bool {
    let Some(name) = binary.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    #[cfg(windows)]
    {
        windows_is_running(name)
    }
    #[cfg(not(windows))]
    {
        unix_is_running(name)
    }
}

/// Windows: `tasklist` filtered to the exact image name, the built-in console tool every supported
/// edition ships (no extra dependency, matching this crate's existing `sc`/`schtasks` idiom).
///
/// A miss prints one `INFO: No tasks are running which match the specified criteria.` line and NO
/// CSV row; a hit's first quoted CSV field is the image name itself. Matching on the QUOTED name
/// therefore distinguishes a hit from the miss message without a CSV parser, and can never be
/// satisfied by the miss text (which never quotes the searched-for name).
///
/// The comparison is CASE-INSENSITIVE: `tasklist` reports a binary's on-disk image name verbatim,
/// which for a system tool is commonly UPPERCASE (`PING.EXE`) regardless of the case a caller
/// queried with, while NTFS treats both as the same file. `/FI "IMAGENAME eq …"` itself already
/// matches case-insensitively — only the post-hoc "did we get a hit" string search was exact-case,
/// which silently turned a real, running match into a reported miss.
#[cfg(windows)]
fn windows_is_running(name: &str) -> bool {
    let filter = format!("IMAGENAME eq {name}");
    let Ok(out) = Command::new("tasklist")
        .args(["/FI", &filter, "/FO", "CSV", "/NH"])
        .hide_console()
        .output()
    else {
        return false;
    };
    let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
    out.status.success() && stdout.contains(&format!("\"{}\"", name.to_lowercase()))
}

/// Unix: `pgrep -x` against the process's own `comm` name — an exact match with no shell-injection
/// surface, unlike piping a name through `ps | grep`. Exit 0 = at least one match, exit 1 = none;
/// any other outcome (the tool missing, a permissions error) is treated as "unknown", the same
/// fail-closed floor as the Windows arm, never as "confirmed running".
#[cfg(not(windows))]
fn unix_is_running(name: &str) -> bool {
    Command::new("pgrep")
        .args(["-x", name])
        .hide_console()
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawn a short-lived child under a SHORT, fixed name — the shape every real component this
    /// module serves actually has (`dig-app`, `dig-chat`, both under ten characters) — rather than
    /// asking `is_running` about THIS test binary's own name.
    ///
    /// That substitution is load-bearing, not incidental (#92 CI red on ubuntu+macos): a `cargo
    /// test` binary's name is `<crate>-<16-hex-char-hash>`, 35+ characters, and Linux/macOS both
    /// truncate a process's reported name well under that (Linux `TASK_COMM_LEN` allows 15 usable
    /// characters; Darwin's is comparably short) — so `pgrep -x <the-untruncated-name>` can never
    /// exact-match the kernel's own truncated value, no matter how correct the detector is. That
    /// false negative is a property of the FIXTURE's name length, not of `unix_is_running`: every
    /// name this crate ever calls it with is short enough to never truncate, so the fix belongs in
    /// the test's choice of vehicle, not in the detector.
    #[cfg(windows)]
    fn spawn_short_named_probe() -> (std::process::Child, &'static str) {
        let child = Command::new("ping")
            .args(["-n", "6", "127.0.0.1"])
            .spawn()
            .expect("ping.exe ships with every supported Windows edition");
        (child, "ping.exe")
    }

    /// See [`spawn_short_named_probe`] (Windows) for why this spawns rather than asking about the
    /// test binary itself. `sleep` is POSIX/coreutils and present on every unix CI image.
    #[cfg(not(windows))]
    fn spawn_short_named_probe() -> (std::process::Child, &'static str) {
        let child = Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("sleep ships on every unix CI runner image");
        (child, "sleep")
    }

    /// The distinguishing fixture: a REAL child process, under a short, fixed, representative
    /// name, running for the entire duration of the check. A stub that always returns `false`
    /// (above) fails this for the right reason — it never asked the OS anything — which is
    /// exactly what proves the assertion is load-bearing rather than vacuously satisfied by an
    /// implementation that reports nothing ever runs.
    #[test]
    fn detects_a_genuinely_running_process_by_its_short_component_style_name() {
        let (mut child, name) = spawn_short_named_probe();
        let detected = is_running(Path::new(name));
        let _ = child.kill();
        let _ = child.wait();
        assert!(detected, "{name} was spawned and should still be running");
    }

    /// The control: a name nothing on the host is running. Paired with the positive case above so
    /// the two together distinguish "a real detector" from either constant answer — a stub
    /// hardcoded to `true` would pass the first test above but fail this one, and a stub hardcoded
    /// to `false` fails the first one.
    #[test]
    fn a_name_nothing_on_the_host_runs_is_not_detected() {
        assert!(!is_running(Path::new(
            "definitely-not-a-real-dig-binary-92-xyz.exe"
        )));
    }
}
