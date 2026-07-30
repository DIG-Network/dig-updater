//! End-to-end scheduler-artifact tests — REAL OS registration (Task Scheduler / systemd /
//! launchd), not the pure content builders [`scheduler::content`] already unit-tests.
//!
//! These mutate real, privileged OS state (a Scheduled Task under
//! `%SystemRoot%\System32\Tasks`, systemd units under `/etc/systemd/system`, a LaunchDaemon under
//! `/Library/LaunchDaemons`), so they require the SAME privilege the artifact itself runs at —
//! Administrator on Windows, root on Unix — the same precondition dig-relay's and dig-dns's own
//! service registration impose. They are `#[ignore]`d so an ordinary `cargo test` never touches
//! real OS scheduler state; the dedicated `scheduler-elevated` job in `.github/workflows/ci.yml`
//! runs them explicitly with `-- --ignored` (Windows: the hosted runner is already
//! Administrator-capable; Unix: invoked under `sudo`).

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use dig_updater_broker::{optout, scheduler};
use tempfile::TempDir;

/// Every test in this file targets the SAME machine-global artifact (one Scheduled Task path /
/// one systemd unit pair / one launchd label — there is no per-test name to isolate on, unlike
/// `lock.rs`'s injectable mutex name). `cargo test` runs tests in the same binary concurrently by
/// default, so without this they race: one test's `uninstall` can land between another's
/// `install` and its `status` check. Each test acquires this for its full body via
/// [`serialize`].
static SCHEDULER_LOCK: Mutex<()> = Mutex::new(());

/// Acquire [`SCHEDULER_LOCK`], recovering it if a PRIOR test panicked while holding it. A plain
/// `.lock().unwrap()` would propagate that poisoning to every test that runs after — one genuine
/// failure would cascade into failing the whole file. The shared OS artifact these tests mutate
/// has no invariant that a panicked test could leave "poisoned" in the Rust-mutex sense (the next
/// test always starts by uninstalling first), so recovering the guard is safe here.
fn serialize() -> MutexGuard<'static, ()> {
    SCHEDULER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A real, existing file path to register — `install` only needs a plausible target program; it
/// never executes it (registration is a pure OS-metadata write), so the running test binary
/// itself is a fine stand-in for the real `dig-updater` executable.
fn fake_exe() -> PathBuf {
    std::env::current_exe().expect("current test binary path")
}

/// A per-test, throwaway state directory the opt-out sentinel (#584) lives in — isolated from the
/// real Admin-only default so these tests never touch machine-global beacon state.
fn state_dir() -> TempDir {
    tempfile::tempdir().expect("throwaway state dir")
}

#[test]
#[ignore = "mutates real OS scheduler state; requires Administrator/root — run via `-- --ignored` \
            in the elevated scheduler CI job"]
fn install_then_status_then_uninstall_round_trips_cleanly() {
    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();

    // Start from a clean slate in case a prior run in this environment left something behind.
    let _ = scheduler::uninstall(state.path());
    assert!(
        !scheduler::status().expect("status").installed(),
        "must start absent"
    );

    scheduler::install(&exe, state.path()).expect("install must succeed when run elevated");
    let status = scheduler::status().expect("status");
    assert!(
        status.installed(),
        "the artifact must report installed: {}",
        status.detail
    );

    scheduler::uninstall(state.path()).expect("uninstall must succeed");
    let status = scheduler::status().expect("status");
    assert!(
        !status.installed(),
        "the artifact must be gone after uninstall: {}",
        status.detail
    );
}

#[test]
#[ignore = "mutates real OS scheduler state; requires Administrator/root — run via `-- --ignored` \
            in the elevated scheduler CI job"]
fn install_is_idempotent_and_uninstall_of_an_absent_schedule_succeeds() {
    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());

    scheduler::install(&exe, state.path()).expect("first install");
    scheduler::install(&exe, state.path())
        .expect("re-install (e.g. a re-run installer) must not error");
    assert!(scheduler::status().expect("status").installed());

    scheduler::uninstall(state.path()).expect("uninstall");
    scheduler::uninstall(state.path())
        .expect("uninstalling an already-absent schedule must succeed");
}

/// Where Task Scheduler keeps the registered task's XML definition on disk — the file whose
/// security descriptor Task Scheduler OWNS (dig_ecosystem#1822).
#[cfg(windows)]
fn windows_definition_file() -> PathBuf {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    std::path::Path::new(&system_root)
        .join("System32")
        .join("Tasks")
        .join("DIG")
        .join("dig-updater")
}

/// The `icacls` listing of `path` — the access-control state a test asserts against.
#[cfg(windows)]
fn icacls_listing(path: &std::path::Path) -> String {
    let output = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .expect("icacls runs from System32");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[cfg(windows)]
#[test]
#[ignore = "mutates real OS scheduler state; requires Administrator — run via `-- --ignored` in \
            the elevated scheduler CI job"]
fn install_must_not_rewrite_the_task_definition_security_descriptor() {
    // dig_ecosystem#1822 — THE REGRESSION GATE. The `\DIG\dig-updater` task vanished from a host
    // with no opt-out marker, i.e. nothing deliberately uninstalled it. The remover was the beacon's
    // OWN `schedule install`, which used to follow `schtasks /Create` with
    // `icacls <definition> /inheritance:r /grant:r Administrators,SYSTEM,OWNER`. That file is Task
    // Scheduler's OWN store, and the authoritative copy of its security descriptor lives in
    // `HKLM\...\Schedule\TaskCache`; a definition whose on-disk SD no longer matches is treated as
    // tampered-with (0x80041321) and DISCARDED from the tree — taking the `\DIG` folder, its only
    // child, with it. That is the folder-level disappearance the host reported.
    //
    // The property asserted is INHERITANCE, not a DACL comparison, because inheritance is exactly
    // what `/inheritance:r` destroys and what every Task Scheduler store file carries: `icacls`
    // marks an inherited ACE `(I)`. A test that merely compared two DACLs could pass on an
    // equivalent-looking explicit rewrite that Task Scheduler would still reject.
    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());

    scheduler::install(&exe, state.path()).expect("install must succeed when run elevated");

    let definition = windows_definition_file();
    assert!(
        definition.exists(),
        "the task definition file must exist at {}",
        definition.display()
    );
    let listing = icacls_listing(&definition);
    assert!(
        listing.contains("(I)"),
        "the task definition's ACL MUST stay INHERITED from Task Scheduler's store — an explicit \
         `/inheritance:r` rewrite makes Task Scheduler treat the task as tampered-with and discard \
         it (dig_ecosystem#1822). Got:\n{listing}"
    );

    scheduler::uninstall(state.path()).expect("uninstall");
}

#[cfg(windows)]
#[test]
#[ignore = "mutates real OS scheduler state; requires Administrator — run via `-- --ignored` in \
            the elevated scheduler CI job"]
fn the_task_definition_file_is_not_writable_by_an_unprivileged_identity() {
    // The security property the deleted `harden_state_dir` call CLAIMED to provide, asserted against
    // the OS default instead of assumed away. Measured on a real Windows 11 host, the default DACL
    // Task Scheduler applies to a definition file grants Administrators and SYSTEM Full, and
    // Authenticated Users / LOCAL SERVICE / NETWORK SERVICE only READ — so the Admin/SYSTEM WRITE
    // bar (SPEC §9.3) is already met without the beacon touching the SD.
    //
    // Read access is deliberately NOT asserted against: `schtasks /Query /XML` prints a task's whole
    // definition to any user, so a readable definition file discloses nothing. WRITE is the bar that
    // matters — a writable definition would let an unprivileged user re-point what SYSTEM executes.
    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());
    scheduler::install(&exe, state.path()).expect("install");

    let listing = icacls_listing(&windows_definition_file());
    for principal in ["Everyone", r"BUILTIN\Users", "Authenticated Users"] {
        for grant in ["(F)", "(M)", "(W)"] {
            assert!(
                !listing.contains(&format!("{principal}:{grant}")),
                "{principal} must not hold {grant} on the task definition file:\n{listing}"
            );
        }
    }
    assert!(
        listing.contains(r"BUILTIN\Administrators:(F)") || listing.contains("S-1-5-32-544"),
        "Administrators must hold Full Control:\n{listing}"
    );
    assert!(
        listing.contains(r"NT AUTHORITY\SYSTEM:(F)") || listing.contains("S-1-5-18"),
        "SYSTEM must hold Full Control:\n{listing}"
    );

    scheduler::uninstall(state.path()).expect("uninstall");
}

#[cfg(windows)]
#[test]
#[ignore = "mutates real OS scheduler state; requires Administrator — run via `-- --ignored` in \
            the elevated scheduler CI job"]
fn a_registered_task_is_still_readable_by_task_scheduler_after_install() {
    // The corruption CONSEQUENCE, observed through Task Scheduler's own parser rather than through
    // the filesystem: `schtasks /Query /XML` makes the service load and re-serialize the task, so a
    // definition the service considers tampered-with fails here (0x80041321) even while the file is
    // still sitting on disk. `/Query /TN` alone is a weaker check — it can answer from the registry
    // cache — so the XML round-trip is the one that exercises the store.
    //
    // The full live proof is stronger still and is NOT a CI test: restart the `Schedule` service and
    // re-query, which is the acceptance step recorded on the ticket. Restarting a hosted runner's
    // Task Scheduler mid-job is not a safe thing to do to the machine running the job.
    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());
    scheduler::install(&exe, state.path()).expect("install");

    let output = std::process::Command::new("schtasks")
        .args(["/Query", "/TN", r"\DIG\dig-updater", "/XML"])
        .output()
        .expect("schtasks runs from System32");
    assert!(
        output.status.success(),
        "Task Scheduler must be able to load + serialize the task it was just given; a store it \
         considers tampered-with fails this and then discards the task (dig_ecosystem#1822). \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );

    scheduler::uninstall(state.path()).expect("uninstall");
}

#[test]
#[ignore = "mutates real OS scheduler state; requires Administrator/root — run via `-- --ignored` \
            in the elevated scheduler CI job"]
fn ensure_self_heals_an_absent_schedule_and_is_idempotent() {
    // #546: `ensure` re-registers a provably-absent schedule (the self-heal), and leaves an
    // already-registered one untouched — the exact behavior a `run`/`check --now` pass relies on to
    // resurrect a deleted daily wake.
    use dig_updater_broker::scheduler::EnsureAction;

    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());
    // The clean-slate uninstall above records a DELIBERATE opt-out (#584); this test models an
    // ACCIDENTAL deletion (a task removed by something other than `schedule uninstall`), so clear
    // the sentinel before exercising the self-heal.
    optout::clear_opted_out(state.path())
        .expect("clear the opt-out to model an accidental deletion");
    assert!(
        !scheduler::status().expect("status").installed(),
        "must start absent"
    );

    // Absent + no opt-out -> re-registered.
    assert_eq!(
        scheduler::ensure(&exe, state.path()).expect("ensure must self-heal an absent schedule"),
        EnsureAction::Reregistered
    );
    assert!(
        scheduler::status().expect("status").installed(),
        "the schedule must exist after the self-heal"
    );

    // Already registered -> left untouched (idempotent).
    assert_eq!(
        scheduler::ensure(&exe, state.path()).expect("ensure on a present schedule must not error"),
        EnsureAction::AlreadyRegistered
    );

    scheduler::uninstall(state.path()).expect("uninstall");
}

#[test]
#[ignore = "mutates real OS scheduler state; requires Administrator/root — run via `-- --ignored` \
            in the elevated scheduler CI job"]
fn ensure_respects_a_deliberate_uninstall_and_install_re_enables() {
    // #584 acceptance: a DELIBERATE `schedule uninstall` must NOT be re-armed by the self-heal, and
    // a later `schedule install` must clear the opt-out so the self-heal works again.
    use dig_updater_broker::scheduler::EnsureAction;

    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();

    // Deliberate uninstall records the opt-out; ensure must honor it even with the task absent.
    scheduler::uninstall(state.path()).expect("deliberate uninstall");
    assert_eq!(
        scheduler::ensure(&exe, state.path()).expect("ensure must honor a deliberate opt-out"),
        EnsureAction::SuppressedByOptOut,
        "an always-on driver must never fight a deliberate `schedule uninstall`"
    );
    assert!(
        !scheduler::status().expect("status").installed(),
        "the schedule must stay removed while opted out"
    );

    // An explicit install clears the opt-out (re-enabling the self-heal) and registers the task.
    scheduler::install(&exe, state.path()).expect("install re-enables");
    assert!(
        !optout::is_opted_out(state.path()),
        "`schedule install` must clear the opt-out sentinel"
    );
    assert_eq!(
        scheduler::ensure(&exe, state.path()).expect("ensure after re-enable"),
        EnsureAction::AlreadyRegistered,
        "with the opt-out cleared and the task present, ensure is a no-op — the self-heal is live again"
    );

    scheduler::uninstall(state.path()).expect("cleanup");
}

#[cfg(windows)]
#[test]
#[ignore = "mutates real OS scheduler state; requires Administrator — run via `-- --ignored` in \
            the elevated scheduler CI job"]
fn windows_uninstall_leaves_the_task_folder_to_task_scheduler() {
    // The inverse of the pre-#1822 expectation, deliberately. The beacon used to `remove_dir` the
    // `%SystemRoot%\System32\Tasks\DIG` folder itself after `schtasks /Delete` — a filesystem write
    // BEHIND Task Scheduler's back, which orphans the matching `TaskCache\Tree\DIG` registry node.
    // Tidying up a cosmetically-empty folder is not worth desynchronizing the store the service
    // reads, so removal (if any) is Task Scheduler's own business now.
    //
    // The load-bearing assertion is that the TASK is gone, which is what `uninstall` promises; the
    // folder's fate is explicitly not the beacon's concern, so nothing is asserted about it beyond
    // the beacon not being the one to delete it.
    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());
    scheduler::install(&exe, state.path()).expect("install");

    let dig_folder = windows_definition_file()
        .parent()
        .expect("the definition file has a containing folder")
        .to_path_buf();
    assert!(
        dig_folder.exists(),
        "sanity: Task Scheduler created {} for the registered task",
        dig_folder.display()
    );

    scheduler::uninstall(state.path()).expect("uninstall");
    assert!(
        !scheduler::status().expect("status").installed(),
        "the TASK must be gone — that is what uninstall promises"
    );
    assert!(
        dig_folder.exists(),
        "the beacon must NOT delete Task Scheduler's own folder out from under it \
         (dig_ecosystem#1822): {}",
        dig_folder.display()
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "mutates real OS scheduler state; requires root — run via `-- --ignored` in the \
            elevated scheduler CI job"]
fn linux_units_are_root_owned_mode_0644() {
    use std::os::unix::fs::MetadataExt;

    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());
    scheduler::install(&exe, state.path()).expect("install");

    for unit in ["dig-updater.service", "dig-updater.timer"] {
        let path = std::path::Path::new("/etc/systemd/system").join(unit);
        let meta = std::fs::metadata(&path).unwrap_or_else(|e| panic!("{unit} exists: {e}"));
        assert_eq!(meta.uid(), 0, "{unit} must be root-owned");
        assert_eq!(meta.mode() & 0o777, 0o644, "{unit} must be mode 0644");
    }

    scheduler::uninstall(state.path()).expect("uninstall");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "mutates real OS scheduler state; requires root — run via `-- --ignored` in the \
            elevated scheduler CI job"]
fn macos_plist_is_root_owned_mode_0644() {
    use std::os::unix::fs::MetadataExt;

    let _guard = serialize();
    let exe = fake_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());
    scheduler::install(&exe, state.path()).expect("install");

    let path = std::path::Path::new("/Library/LaunchDaemons/net.dignetwork.dig-updater.plist");
    let meta = std::fs::metadata(path).expect("plist exists");
    assert_eq!(meta.uid(), 0, "the plist must be root-owned");
    assert_eq!(meta.mode() & 0o777, 0o644, "the plist must be mode 0644");

    scheduler::uninstall(state.path()).expect("uninstall");
}
