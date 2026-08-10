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

/// A target program to register whose CONTAINING DIRECTORY is privileged-owned — the precondition
/// `scheduler::install`/`ensure` now enforce (#2334: a SYSTEM/root daily task must not run a binary
/// from a user-writable directory, or one elevation approval becomes a permanent foothold).
///
/// The exe file need not exist: registration is a pure OS-metadata write that never executes it, and
/// the guard only stats the PARENT directory. We make that directory privileged-owned via the public
/// [`secure::claim_privileged_ownership`] (Windows: sets the owner to Administrators; Unix: a no-op,
/// since a root-run test already creates root-owned `0700` directories). The returned [`TempDir`]
/// MUST be held for the test's duration — dropping it deletes the directory out from under the OS
/// registration.
fn privileged_exe() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("throwaway exe dir");
    dig_updater_broker::secure::claim_privileged_ownership(dir.path())
        .expect("make the exe directory privileged-owned");
    let exe = dir.path().join("dig-updater");
    (dir, exe)
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
    let (_exe_dir, exe) = privileged_exe();
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
    let (_exe_dir, exe) = privileged_exe();
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

/// One access-control entry parsed out of an `icacls` listing: WHO, and WHICH rights.
///
/// Parsed rather than string-matched because the exact rendering varies by host, and an assertion
/// written against one host's spelling silently stops testing anything on another. The same ACE shows
/// up as `BUILTIN\Administrators:(F)` on one machine and `BUILTIN\Administrators:(I)(F)` on another —
/// identical ACCESS, different provenance — and a `contains("Administrators:(F)")` check passes on the
/// first and fails on the second while the property under test holds on both.
#[cfg(windows)]
struct Ace {
    /// The principal, e.g. `BUILTIN\Administrators`.
    principal: String,
    /// The granted rights, with the INHERITANCE flags (`I`, `OI`, `CI`, `IO`, `NP`) removed — those
    /// describe how the ACE was acquired, not what it permits.
    rights: Vec<String>,
}

#[cfg(windows)]
impl Ace {
    /// Whether this ACE permits MODIFYING the object: Full, Modify, Write, Delete, or either of the
    /// two rights that let a holder rewrite its way to write access (change the DACL, take ownership).
    fn permits_modification(&self) -> bool {
        const WRITE_CLASS: [&str; 6] = ["F", "M", "W", "D", "WDAC", "WO"];
        self.rights
            .iter()
            .any(|r| WRITE_CLASS.contains(&r.as_str()))
    }

    /// Whether the principal is one an ordinary local user belongs to — the identities that must hold
    /// no write-class right on a file naming what SYSTEM executes.
    fn is_unprivileged(&self) -> bool {
        const UNPRIVILEGED: [&str; 3] = ["Everyone", r"BUILTIN\Users", r"Authenticated Users"];
        UNPRIVILEGED
            .iter()
            .any(|u| self.principal.ends_with(u) || self.principal == *u)
    }
}

/// Parse the `icacls` listing of `path` into its ACEs.
///
/// `icacls` puts the first ACE on the same line as the path and indents the rest, so the path is
/// stripped EXPLICITLY (the caller knows it) rather than guessed at by splitting on whitespace. That
/// matters: a principal can contain a space — `NT AUTHORITY\Authenticated Users`, the one identity an
/// ordinary user actually belongs to — and taking the last space-separated token would reduce it to
/// `Users`, which matches none of the unprivileged names and would make the write-bar assertion
/// vacuously pass for exactly the principal it exists to check.
#[cfg(windows)]
fn parse_icacls(listing: &str, path: &std::path::Path) -> Vec<Ace> {
    let path_prefix = path.display().to_string();
    listing
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let entry = line
                .strip_prefix(path_prefix.as_str())
                .unwrap_or(line)
                .trim();
            let (principal, groups) = entry.split_once(":(")?;
            let rights = groups
                .trim_end_matches(')')
                .split(")(")
                .flat_map(|group| group.split(','))
                .map(|right| right.trim().to_string())
                .filter(|right| !["I", "OI", "CI", "IO", "NP"].contains(&right.as_str()))
                .collect();
            Some(Ace {
                principal: principal.trim().to_string(),
                rights,
            })
        })
        .collect()
}

/// Real `icacls` listings captured from live hosts, so the parser is tested against the renderings it
/// must actually cope with rather than against an idealized one this file invented.
#[cfg(windows)]
mod real_listings {
    /// A Windows 11 desktop's OS-default task definition — note `Authenticated Users`, whose space in
    /// the principal name is the parser's sharp edge, and the mix of explicit and `(I)`-inherited ACEs.
    pub const DESKTOP_DEFAULT: &str = concat!(
        r"C:\Windows\System32\Tasks\DIG\dig-updater BUILTIN\Administrators:(F)",
        "\n                                          NT AUTHORITY\\SYSTEM:(F)",
        "\n                                          NT AUTHORITY\\LOCAL SERVICE:(RX)",
        "\n                                          NT AUTHORITY\\Authenticated Users:(R)",
        "\n                                          BUILTIN\\Administrators:(I)(R,W,D,WDAC,WO)",
        "\n\nSuccessfully processed 1 files; Failed processing 0 files\n"
    );

    /// The GitHub Windows runner's OS-default task definition — Administrators holds Full only via an
    /// INHERITED ace, which is why the assertions must speak about access rather than about spelling.
    pub const RUNNER_DEFAULT: &str = concat!(
        r"C:\Windows\System32\Tasks\DIG\dig-updater NT AUTHORITY\SYSTEM:(R)",
        "\n                                          BUILTIN\\Administrators:(I)(R,W,D,WDAC,WO)",
        "\n                                          NT AUTHORITY\\SYSTEM:(I)(R,W,D,WDAC,WO)",
        "\n                                          BUILTIN\\Administrators:(I)(F)",
        "\n\nSuccessfully processed 1 files; Failed processing 0 files\n"
    );

    /// What the DEFECTIVE code produced (dig_ecosystem#1822): three explicit ACEs and NO inherited
    /// one, the `icacls /inheritance:r /grant:r` fingerprint that got the task discarded.
    pub const INHERITANCE_STRIPPED: &str = concat!(
        r"C:\Windows\System32\Tasks\DIG\dig-updater OWNER RIGHTS:(F)",
        "\n                                          BUILTIN\\Administrators:(F)",
        "\n                                          NT AUTHORITY\\SYSTEM:(F)",
        "\n\nSuccessfully processed 1 files; Failed processing 0 files\n"
    );
}

#[cfg(windows)]
#[test]
fn parse_icacls_reads_a_principal_whose_name_contains_a_space() {
    // THE trap this parser exists to avoid. `NT AUTHORITY\Authenticated Users` is the identity an
    // ordinary local user belongs to, so if it parses as `Users` the unprivileged write-bar check
    // silently stops examining it — a green assertion about a principal it never looked at.
    let aces = parse_icacls(real_listings::DESKTOP_DEFAULT, &windows_definition_file());
    let authenticated = aces
        .iter()
        .find(|a| a.principal == r"NT AUTHORITY\Authenticated Users")
        .expect("Authenticated Users must parse with its space intact");
    assert!(
        authenticated.is_unprivileged(),
        "and must be classified as an unprivileged identity"
    );
    assert_eq!(authenticated.rights, vec!["R"]);
    assert!(
        !authenticated.permits_modification(),
        "READ is not modification — this is why the OS default already meets the write bar"
    );
}

#[cfg(windows)]
#[test]
fn parse_icacls_reports_access_independently_of_how_the_ace_was_inherited() {
    // The runner grants Administrators Full only through an INHERITED ace. Access is access: an
    // assertion written against `Administrators:(F)` would fail here while the property holds, which is
    // exactly the false RED that a string-matched version of this test produced.
    let aces = parse_icacls(real_listings::RUNNER_DEFAULT, &windows_definition_file());
    assert!(
        aces.iter()
            .any(|a| a.principal.ends_with("Administrators") && a.permits_modification()),
        "Administrators holds Full via an inherited ACE on this host"
    );
    assert!(
        aces.iter()
            .any(|a| a.principal.ends_with("SYSTEM") && a.permits_modification()),
        "SYSTEM holds write via an inherited ACE on this host"
    );
    assert!(
        !aces.iter().any(|a| a.is_unprivileged()),
        "and this host's default grants an unprivileged identity nothing at all"
    );
}

#[cfg(windows)]
#[test]
fn an_inheritance_stripped_listing_is_distinguishable_from_every_os_default() {
    // The discriminator the regression gate keys on, asserted on the REAL captured listings: both
    // OS defaults carry inherited ACEs, and the output of the defective code carries none. A gate that
    // could not tell those apart would not be a gate.
    for (label, listing) in [
        ("desktop", real_listings::DESKTOP_DEFAULT),
        ("runner", real_listings::RUNNER_DEFAULT),
    ] {
        assert!(
            listing.contains("(I)"),
            "the {label} OS default must carry inherited ACEs"
        );
    }
    assert!(
        !real_listings::INHERITANCE_STRIPPED.contains("(I)"),
        "the defective code's output carries none — that difference IS the defect"
    );
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
    let (_exe_dir, exe) = privileged_exe();
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
    let (_exe_dir, exe) = privileged_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());
    scheduler::install(&exe, state.path()).expect("install");

    let definition = windows_definition_file();
    let listing = icacls_listing(&definition);
    let aces = parse_icacls(&listing, &definition);
    assert!(
        !aces.is_empty(),
        "the listing must parse into at least one ACE, or this test asserts nothing:\n{listing}"
    );

    let writable_by = |predicate: fn(&Ace) -> bool| -> bool {
        aces.iter()
            .any(|ace| predicate(ace) && ace.permits_modification())
    };
    assert!(
        !writable_by(Ace::is_unprivileged),
        "no unprivileged identity may MODIFY the file naming what SYSTEM executes:\n{listing}"
    );
    assert!(
        writable_by(|ace| ace.principal.ends_with("Administrators")),
        "Administrators must retain write access, or the beacon could not manage its own task:\n{listing}"
    );
    assert!(
        writable_by(|ace| ace.principal.ends_with("SYSTEM")),
        "SYSTEM must retain write access — it is the identity the task runs as:\n{listing}"
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
    let (_exe_dir, exe) = privileged_exe();
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
    let (_exe_dir, exe) = privileged_exe();
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
    let (_exe_dir, exe) = privileged_exe();
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
    let (_exe_dir, exe) = privileged_exe();
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
    let (_exe_dir, exe) = privileged_exe();
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
    let (_exe_dir, exe) = privileged_exe();
    let state = state_dir();
    let _ = scheduler::uninstall(state.path());
    scheduler::install(&exe, state.path()).expect("install");

    let path = std::path::Path::new("/Library/LaunchDaemons/net.dignetwork.dig-updater.plist");
    let meta = std::fs::metadata(path).expect("plist exists");
    assert_eq!(meta.uid(), 0, "the plist must be root-owned");
    assert_eq!(meta.mode() & 0o777, 0o644, "the plist must be mode 0644");

    scheduler::uninstall(state.path()).expect("uninstall");
}
