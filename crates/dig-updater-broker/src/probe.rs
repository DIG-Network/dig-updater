//! The bounded version probe every enumeration and health check runs through (SPEC §9.5, §9.6).
//!
//! The probe answers one question — "what version is the binary at this path?" — by spawning
//! `<path> --version` and reading what it prints. The subtlety is what happens when the binary
//! DOESN'T answer.
//!
//! A CLI or a service executable answers `--version` and exits in milliseconds. A **per-user
//! desktop daemon does not**: `dig-app` (dig_ecosystem#1746) parses no arguments at all — its
//! `main` builds its agent and mounts a tray event loop that owns the process for its lifetime — so
//! `dig-app --version` mounts a tray and never returns. The shared
//! [`dig_release_resolver::detect_installed_version`] probe waits with an unbounded
//! `Command::output()`, which on such a binary blocks the whole beacon pass FOREVER and leaves a
//! stray daemon running under the beacon's identity. That happens at ENUMERATION, before any
//! install — so one unanswering binary on disk is enough to stop a host updating anything, ever.
//!
//! This module bounds that wait. A binary that has not answered within [`PROBE_BUDGET`] is KILLED
//! and reported as `Present("")` — "installed, but its version could not be read" — which the
//! shared decision matrix treats as unparseable, so the component is reinstalled and, crucially,
//! [`crate::health::check_health`] REJECTS it. An unanswering component therefore fails its gate
//! and rolls back, instead of hanging every other component's update behind it.
//!
//! Bounding the wait is what makes a daemon component SAFE to enumerate; it does not make one
//! installable. A component the beacon is to keep current MUST answer `--version` and exit.

use std::io;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use dig_release_resolver::DetectedVersion;

/// How long a binary is given to answer `--version` before it is killed and reported unreadable.
///
/// Sized for the slowest legitimate answer, not the fastest: a cold-cache first spawn of a large
/// binary on a loaded host (or one being scanned by an endpoint-protection filter driver) can take
/// seconds, and a false "unreadable" would roll back a perfectly good install. Ten seconds is far
/// above that and far below anything a person would call a hang.
pub const PROBE_BUDGET: Duration = Duration::from_secs(10);

/// How often the spawned probe is polled for completion. Short enough that the common
/// answers-immediately case adds no perceptible latency to a pass.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Detect the version of the binary installed at `path`, bounded by [`PROBE_BUDGET`].
///
/// Returns [`DetectedVersion::Absent`] when nothing is installed there, and otherwise
/// [`DetectedVersion::Present`] with whatever `--version` printed — or with an empty string when
/// the binary could not be spawned, exited non-zero, or (the case this exists for) did not answer
/// within the budget and was killed.
#[must_use]
pub fn detect_installed_version(path: &Path) -> DetectedVersion {
    bounded_probe(path, PROBE_BUDGET, spawn_version_query)
}

/// Spawn `<path> --version` with its stdout captured — the production probe launch.
fn spawn_version_query(path: &Path) -> io::Result<Child> {
    Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// The body of [`detect_installed_version`], with the child launch INJECTED so both the
/// answers-promptly and the never-answers branches can be exercised against real child processes
/// without needing a purpose-built fixture binary on disk.
fn bounded_probe(
    path: &Path,
    budget: Duration,
    spawn: impl FnOnce(&Path) -> io::Result<Child>,
) -> DetectedVersion {
    if !path.exists() {
        return DetectedVersion::Absent;
    }
    // From here the binary IS installed, so every failure to read its version is still `Present` —
    // present-but-unreadable, which the decision matrix reinstalls and the health gate rejects.
    let Ok(mut child) = spawn(path) else {
        return DetectedVersion::Present(String::new());
    };
    match wait_within(&mut child, budget) {
        Some(true) => DetectedVersion::Present(read_stdout(&mut child)),
        // Exited, but non-zero: it has no version to report.
        Some(false) => DetectedVersion::Present(String::new()),
        None => {
            kill_and_reap(&mut child);
            DetectedVersion::Present(String::new())
        }
    }
}

/// Wait for `child` for at most `budget`, polling rather than blocking so the deadline is real.
///
/// `Some(true)` = exited successfully, `Some(false)` = exited unsuccessfully (or its status could
/// not be read), `None` = still running when the budget elapsed.
fn wait_within(child: &mut Child, budget: Duration) -> Option<bool> {
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.success()),
            // The status is unreadable; the child is finished either way, so stop waiting on it.
            Err(_) => return Some(false),
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Kill a probe that outlasted its budget and reap it, so a bounded probe leaves no orphan behind.
/// Both calls are best-effort: the child may have exited in the race between the deadline check and
/// here, and a failure to signal an already-dead process is not an error worth reporting.
fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Read whatever the finished probe wrote to stdout, trimmed. An unreadable pipe yields an empty
/// string — the same "present but unreadable" answer as a failed spawn.
fn read_stdout(child: &mut Child) -> String {
    use std::io::Read;
    let Some(mut stdout) = child.stdout.take() else {
        return String::new();
    };
    let mut buf = String::new();
    match stdout.read_to_string(&mut buf) {
        Ok(_) => buf.trim().to_string(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::check_health;

    /// A path that certainly exists, so the tests exercise the SPAWN branches rather than the
    /// nothing-installed short-circuit. The probe never reads the file itself — the injected launch
    /// decides what actually runs — so the test binary's own path is a fine stand-in.
    fn installed_path() -> std::path::PathBuf {
        std::env::current_exe().expect("the test binary's own path")
    }

    /// Launch a real child that ignores its arguments and keeps running — dig-app's shape exactly.
    /// Long enough that it cannot exit on its own inside any test's budget, so a test that passes
    /// can only have passed because the probe killed it.
    fn spawn_never_answers(_: &Path) -> io::Result<Child> {
        #[cfg(windows)]
        let mut cmd = {
            let mut c = Command::new("cmd");
            c.args(["/c", "ping -n 300 127.0.0.1"]);
            c
        };
        #[cfg(not(windows))]
        let mut cmd = {
            let mut c = Command::new("sh");
            c.args(["-c", "sleep 300"]);
            c
        };
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
    }

    /// Launch a real child that answers promptly with `text` and exits — a well-behaved CLI.
    fn spawn_answering(text: &'static str) -> impl FnOnce(&Path) -> io::Result<Child> {
        move |_: &Path| {
            #[cfg(windows)]
            let mut cmd = {
                let mut c = Command::new("cmd");
                c.args(["/c", &format!("echo {text}")]);
                c
            };
            #[cfg(not(windows))]
            let mut cmd = {
                let mut c = Command::new("sh");
                c.args(["-c", &format!("echo '{text}'")]);
                c
            };
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
        }
    }

    /// A child that exits NON-ZERO promptly — the binary ran but rejected `--version`.
    fn spawn_rejecting(_: &Path) -> io::Result<Child> {
        #[cfg(windows)]
        let mut cmd = {
            let mut c = Command::new("cmd");
            c.args(["/c", "exit 1"]);
            c
        };
        #[cfg(not(windows))]
        let mut cmd = {
            let mut c = Command::new("sh");
            c.args(["-c", "exit 1"]);
            c
        };
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
    }

    /// THE POINT (dig_ecosystem#1746): a binary that never answers `--version` — a tray daemon like
    /// dig-app — must not stall the probe. The unbounded `Command::output()` this replaces would
    /// never return here, so the assertion is only reachable because the wait is bounded.
    #[test]
    fn a_binary_that_never_answers_is_bounded_not_awaited_forever() {
        let started = Instant::now();
        let detected = bounded_probe(
            &installed_path(),
            Duration::from_millis(200),
            spawn_never_answers,
        );
        let elapsed = started.elapsed();

        assert_eq!(
            detected,
            DetectedVersion::Present(String::new()),
            "an unanswering binary is present-but-unreadable, never Absent — it IS installed"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "the probe returned only after {elapsed:?}; it is not bounded by its budget"
        );
    }

    /// The bound is only useful if the health gate then REJECTS the unreadable answer: the pass must
    /// roll such a component back, not accept it as current. Asserting the probe's return value
    /// alone would leave that link unproven.
    #[test]
    fn an_unanswering_binary_fails_the_health_gate() {
        let path = installed_path();
        let detected = bounded_probe(&path, Duration::from_millis(200), spawn_never_answers);
        let probe = |_: &Path| detected.clone();

        let err = check_health(&path, "3.0.0", &probe)
            .expect_err("a component that cannot report its version must not pass its health gate");
        assert!(
            err.contains("version check"),
            "expected a version-check failure, got: {err}"
        );
    }

    /// A probe that outlasts its budget is KILLED, so bounding the wait does not trade a hung pass
    /// for an accumulating pile of orphaned daemons. Proven by the child's own exit status: a killed
    /// `sleep 300` reports unsuccessful termination, whereas an un-killed one would still be running
    /// and `try_wait` would report nothing at all.
    #[test]
    fn a_probe_that_outlasts_its_budget_is_killed() {
        let mut child = spawn_never_answers(Path::new("unused")).expect("a long-running child");
        assert!(
            wait_within(&mut child, Duration::from_millis(200)).is_none(),
            "the fixture child must still be running when the budget elapses, or it proves nothing"
        );

        kill_and_reap(&mut child);

        let status = child
            .try_wait()
            .expect("a reaped child's status is readable");
        assert!(
            status.is_some(),
            "the child is still running after kill_and_reap — the probe leaks a daemon per pass"
        );
    }

    /// The common case is untouched: a binary that answers promptly has its version read verbatim,
    /// so bounding the wait costs well-behaved components nothing.
    #[test]
    fn a_binary_that_answers_promptly_has_its_version_read() {
        assert_eq!(
            bounded_probe(
                &installed_path(),
                PROBE_BUDGET,
                spawn_answering("dig-app 3.0.0")
            ),
            DetectedVersion::Present("dig-app 3.0.0".to_string()),
        );
    }

    /// …and that prompt answer satisfies the health gate, closing the loop the unreadable case opens.
    #[test]
    fn a_promptly_answered_matching_version_passes_the_health_gate() {
        let path = installed_path();
        let detected = bounded_probe(&path, PROBE_BUDGET, spawn_answering("dig-app 3.0.0"));
        let probe = |_: &Path| detected.clone();
        assert!(check_health(&path, "3.0.0", &probe).is_ok());
    }

    #[test]
    fn a_binary_that_rejects_the_flag_is_present_but_unreadable() {
        assert_eq!(
            bounded_probe(&installed_path(), PROBE_BUDGET, spawn_rejecting),
            DetectedVersion::Present(String::new()),
        );
    }

    #[test]
    fn nothing_installed_is_absent_without_spawning_anything() {
        let missing = installed_path().with_file_name("dig-updater-no-such-binary-1746");
        assert_eq!(
            bounded_probe(&missing, PROBE_BUDGET, |_| panic!(
                "an absent binary must not be spawned"
            )),
            DetectedVersion::Absent,
        );
    }

    #[test]
    fn an_unspawnable_binary_is_present_but_unreadable() {
        // The file exists but cannot be executed (a directory, say) — still installed, still
        // unreadable, so the same answer as a killed probe.
        assert_eq!(
            bounded_probe(&installed_path(), PROBE_BUDGET, |_| Err(io::Error::other(
                "exec format error"
            ))),
            DetectedVersion::Present(String::new()),
        );
    }
}
