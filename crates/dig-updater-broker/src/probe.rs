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
//! and reported as `Present("")` — "installed, but its version could not be read" — which the shared
//! decision matrix treats as unparseable. For a component declared safe to probe, that means the
//! bytes are corrupt or partial: it is reinstalled and [`crate::health::check_health`] REJECTS
//! anything that still cannot report the promised version, so it rolls back rather than hanging every
//! other component's update behind it.
//!
//! **Bounding the wait does NOT make an unanswering binary safe to run.** It stops the pass hanging;
//! it does not un-run whatever the binary did when it started, and this parent is SYSTEM/root. A
//! binary whose behaviour on `--version` is not known to be "print and exit" is therefore declared
//! [`VersionEvidence::UnsafeToProbe`](crate::plan::VersionEvidence::UnsafeToProbe) and is never
//! spawned by the planner at all — the exec is not attempted, so neither the hang nor the side
//! effects are possible. `dig-app` ≤ 3.3.0 is exactly that case (dig_ecosystem#1746/#1749): its
//! `--version` boots the identity agent, seals a master seed on first run and binds a signing
//! socket. The two mechanisms are layered, not alternatives: the declaration prevents the exec, this
//! bound + [`apply_minimal_env`] contain a probe of a binary believed safe that turns out not to be.
//!
//! A component the beacon is to keep current MUST answer `--version` on stdout and EXIT.

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
    let mut command = Command::new(path);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    apply_minimal_env(&mut command);
    command.spawn()
}

/// The ONLY environment variables a probe child inherits — everything else is cleared.
///
/// Just the two the Windows loader and Win32 initialization need to resolve SYSTEM DLLs. Two classes
/// are deliberately absent, for two different reasons:
///
/// - **Where a user's data lives** — `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, every `XDG_*`.
///   A probed program that resolves a data directory on startup would otherwise resolve the beacon's
///   own privileged profile, or a `sudo -E` caller's directory.
/// - **Where code can be loaded from** — notably `PATH`, which on Windows is the tail of the DLL
///   search order for the child. Passing it would let a directory the beacon did not choose
///   contribute code to a process it launched at machine privilege, which is the same objection this
///   allowlist exists to make. It is not needed: `PATH` plays no part in unix library resolution
///   (that is `ld.so` + RPATH), and every DIG component was verified to print its version and exit
///   in well under a second with only these two variables set.
const PROBE_ENV_ALLOWLIST: [&str; 2] = ["SystemRoot", "SystemDrive"];

/// Clear the probe child's inherited environment down to [`PROBE_ENV_ALLOWLIST`].
///
/// The probe executes a binary whose behaviour the beacon does not control, from a privileged parent,
/// so the environment it inherits is an input to someone else's code. Two concrete harms this closes:
///
/// - a probed program that resolves a data directory on startup would otherwise write into whatever
///   profile the BEACON runs under (SYSTEM's `%LOCALAPPDATA%`, root's `$HOME`);
/// - under `sudo -E dig-updater run` — a documented operator action — the invoking user's
///   `$HOME`/`$XDG_DATA_HOME` are inherited all the way down, so a probed program would plant
///   ROOT-OWNED directories inside that user's own data dir and permanently break it for them
///   (dig_ecosystem#1748's class, reached through the probe).
///
/// This is defence in depth, NOT the primary control: a binary that must not be executed is declared
/// [`VersionEvidence::UnsafeToProbe`](crate::plan::VersionEvidence::UnsafeToProbe) and is never
/// spawned at all. Clearing the environment bounds the damage from a binary that IS probed and
/// nevertheless misbehaves.
fn apply_minimal_env(command: &mut Command) {
    command.env_clear();
    for (key, value) in inherited_allowlisted_env() {
        command.env(key, value);
    }
    command.current_dir(system_working_dir());
}

/// The system-owned directory a probe child runs in.
///
/// Never the beacon's inherited working directory. On Windows the CWD is searched for DLLs, so a
/// probe launched from a user-writable directory — which `dig-updater run` from an elevated prompt
/// really is — would let a DLL planted there satisfy a genuinely-missing import in the child, as
/// machine-privileged code. `%SystemRoot%\System32` and `/` are chosen because they are
/// system-owned and certain to exist; the probed path itself is absolute, so nothing about resolving
/// the program depends on this.
#[must_use]
fn system_working_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        std::path::PathBuf::from(root).join("System32")
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/")
    }
}

/// The allowlisted variables actually present in this process's environment, as owned pairs.
///
/// Split out as a pure function so the POLICY is unit-testable on every OS without spawning anything:
/// a test can set a `HOME`/`XDG_DATA_HOME`/`LOCALAPPDATA` canary and assert it is not in the result.
#[must_use]
fn inherited_allowlisted_env() -> Vec<(String, String)> {
    PROBE_ENV_ALLOWLIST
        .iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| ((*key).to_string(), value))
        })
        .collect()
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

    /// For a SAFE-TO-PROBE component, the bound is only useful if the health gate then rejects the
    /// unreadable answer: the pass must roll such a component back, not accept it as current.
    /// Asserting the probe's return value alone would leave that link unproven. (A component declared
    /// unsafe to probe never reaches this path at all — it is never spawned.)
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

    /// The probe child MUST NOT inherit any variable that tells a program where a user's data lives.
    ///
    /// This is the `sudo -E dig-updater run` leak in miniature: with the parent's environment
    /// inherited, a probed program resolving its data directory on startup writes into the BEACON's
    /// profile (SYSTEM's `%LOCALAPPDATA%`, root's `$HOME`) or — worse, under `sudo -E` — plants
    /// root-owned directories inside the invoking user's own data dir. Canaries are set here rather
    /// than assumed present, so the assertion cannot pass merely because the CI runner happens not to
    /// define them.
    #[test]
    fn the_probe_child_inherits_no_profile_or_xdg_variables() {
        // SAFETY: single-threaded within this test; the canaries are unique to it and only read back
        // through `inherited_allowlisted_env`, which is what the production spawn uses.
        let leaky = [
            ("HOME", "/home/canary-1746"),
            ("USERPROFILE", r"C:\Users\canary-1746"),
            ("LOCALAPPDATA", r"C:\Users\canary-1746\AppData\Local"),
            ("APPDATA", r"C:\Users\canary-1746\AppData\Roaming"),
            ("XDG_DATA_HOME", "/home/canary-1746/.local/share"),
            ("XDG_CONFIG_HOME", "/home/canary-1746/.config"),
        ];
        for (key, value) in leaky {
            std::env::set_var(key, value);
        }

        let inherited = inherited_allowlisted_env();

        for (key, _) in leaky {
            assert!(
                !inherited.iter().any(|(k, _)| k == key),
                "{key} reaches the probe child — a probed program would resolve the beacon's (or a \
                 sudo -E caller's) data directory from it"
            );
        }
        assert!(
            inherited
                .iter()
                .all(|(k, _)| PROBE_ENV_ALLOWLIST.contains(&k.as_str())),
            "only allowlisted variables may be passed: {inherited:?}"
        );
        // `PATH` is excluded on purpose and is asserted separately from the canaries above, because
        // mutating this process's own `PATH` mid-suite would disturb sibling tests that spawn shells.
        // On Windows it is the tail of the child's DLL search order, and no DIG component needs it to
        // print its version.
        assert!(
            !PROBE_ENV_ALLOWLIST.contains(&"PATH"),
            "PATH must not reach a probe child — it is a code-loading input on Windows"
        );
    }

    /// `env_clear` is actually APPLIED to the production launch — the allowlist policy above is only
    /// worth anything if the spawn honours it. Proven by executing a real child that prints the
    /// canary: unix only, because it needs a fixture that ignores `--version` and reports an
    /// environment variable, which a shebang script gives portably on unix alone. This is also the
    /// platform on which the `sudo -E` leak was demonstrated.
    #[cfg(unix)]
    #[test]
    fn the_production_spawn_really_clears_the_environment() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temp dir");
        let script = dir.path().join("prints-xdg");
        let mut file = std::fs::File::create(&script).expect("create fixture");
        // Ignores its arguments entirely and prints the variable — dig-app's shape, minus the harm.
        writeln!(file, "#!/bin/sh\necho \"[${{XDG_DATA_HOME:-unset}}]\"").expect("write fixture");
        file.flush().expect("flush");
        drop(file);
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("make executable");

        std::env::set_var("XDG_DATA_HOME", "/home/canary-1746/.local/share");

        let detected = bounded_probe(&script, PROBE_BUDGET, spawn_version_query);

        assert_eq!(
            detected,
            DetectedVersion::Present("[unset]".to_string()),
            "the probe child saw XDG_DATA_HOME — the production spawn does not clear its environment"
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
