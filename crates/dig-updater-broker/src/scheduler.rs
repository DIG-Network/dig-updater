//! The per-OS scheduler artifact that WAKES a pass daily (SPEC §8.1, §8.2, #504-F).
//!
//! The beacon itself never sleeps-and-loops — it is invoked, runs one pass ([`crate::Broker::run_once`]),
//! and exits (SPEC §8.1). Something OUTSIDE the beacon has to invoke it on a schedule; this module
//! registers, removes, and reports on that OUTSIDE thing, in the OS-native form dig-installer's
//! own service registrations already use (`dns::plan` + `dns::{macos,linux}` in that repo):
//!
//! | OS      | Artifact                                              | Runs as        |
//! |---------|--------------------------------------------------------|-----------------|
//! | Windows | a Scheduled Task at [`content::WINDOWS_TASK_PATH`]     | `S-1-5-18` (SYSTEM) |
//! | Linux   | a systemd `.service` + `.timer` pair                    | root (via systemd) |
//! | macOS   | a `LaunchDaemon` plist at [`content::LAUNCHD_LABEL`]    | root |
//!
//! Every artifact runs `<exe> run` (a full [`crate::Broker::run_once`] pass, not the dry
//! [`crate::Broker::dry_check`]) daily, jittered, with a native or baked-in "catch up a missed
//! run" setting — Windows `StartWhenAvailable`, systemd `Persistent=true`, launchd `RunAtLoad` —
//! so a machine that was off past the trigger time still gets a prompt update on its next boot
//! (SPEC boot recovery) instead of waiting a full day. [`content`] holds the pure, cross-platform-
//! testable TEXT of each artifact; this module holds the OS calls that register it, which — like
//! every native install path in this crate — resolve their system tool by ABSOLUTE, trusted path
//! ([`crate::install::trusted_absolute`]), never a bare name resolved through `PATH`.
//!
//! `install`/`uninstall` both require the privilege the artifact itself will run at
//! (Administrator on Windows, root on Unix) — the same precondition dig-relay's and dig-dns's own
//! service registration already impose, and for the same reason: registering a SYSTEM/root-run
//! schedule is itself a privileged operation.

pub mod content;

use std::path::Path;

use crate::error::BrokerError;

/// The determined presence of the daily scheduler artifact — with the crucial distinction between
/// "provably absent" and "presence could not be determined" (#546).
///
/// The pre-#546 code collapsed both into a single `installed: bool`, so a registered-but-ACL-locked
/// task (a `schtasks /Query` that failed with *access denied*) reported exactly like a genuinely
/// missing one — which both lied to `dig-updater schedule status` AND would have driven the
/// self-heal ([`ensure`]) to needlessly recreate a task that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulePresence {
    /// The scheduler artifact is registered.
    Registered,
    /// The scheduler artifact is provably ABSENT (the OS reported "no such task"). This is the ONLY
    /// state the self-heal re-registers from.
    Absent,
    /// The artifact's presence could not be determined (e.g. the query was access-denied). NOT the
    /// same as [`Self::Absent`] — the self-heal must never recreate a task that might already exist.
    Unknown,
}

/// Whether the daily schedule is registered, and a human detail for `dig-updater schedule status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleStatus {
    /// The determined presence of the artifact with the OS scheduler right now.
    pub presence: SchedulePresence,
    /// A human-readable detail (the artifact path/label, or why it is absent/unreadable).
    pub detail: String,
}

impl ScheduleStatus {
    /// A `Registered` status carrying `detail`.
    fn registered(detail: String) -> Self {
        Self {
            presence: SchedulePresence::Registered,
            detail,
        }
    }
    /// An `Absent` status carrying `detail`.
    fn absent(detail: String) -> Self {
        Self {
            presence: SchedulePresence::Absent,
            detail,
        }
    }
    /// An `Unknown` (presence-undeterminable) status carrying `detail`.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn unknown(detail: String) -> Self {
        Self {
            presence: SchedulePresence::Unknown,
            detail,
        }
    }

    /// Whether the artifact is registered (`presence == Registered`). The convenience predicate the
    /// CLI + status-mirror read; a `Unknown`/`Absent` presence both answer `false`, but callers that
    /// must NOT act on "can't tell" (the self-heal) inspect [`Self::presence`] directly.
    #[must_use]
    pub fn installed(&self) -> bool {
        self.presence == SchedulePresence::Registered
    }
}

/// What [`ensure`] decided to do about the daily schedule this pass.
///
/// A value (not just a side effect) so the self-heal DECISION is unit-testable without touching the
/// OS ([`ensure_decision`]) and so a caller/log can report which branch ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureAction {
    /// Already registered — left untouched.
    AlreadyRegistered,
    /// Presence could not be determined (e.g. access-denied) — left untouched, never recreated.
    LeftUnknown,
    /// Provably absent — (re-)registered this pass.
    Reregistered,
    /// The daily schedule was DELIBERATELY removed (an Admin-owned opt-out sentinel is present, see
    /// [`crate::optout`]) — the self-heal honored that choice and did NOT re-register (#584).
    SuppressedByOptOut,
}

/// Register the daily scheduler artifact that invokes `<exe> run`, CLEARING any prior opt-out.
///
/// Clearing the opt-out sentinel ([`crate::optout`]) is what re-enables the self-heal / always-on
/// re-arm after a previous `uninstall`: an explicit `install` is the operator saying "I want the
/// schedule again". The clear happens only AFTER a successful registration, so a failed install
/// never silently re-arms a deliberate opt-out.
///
/// # Errors
///
/// [`BrokerError::Io`] if the caller lacks the privilege to register a SYSTEM/root-run schedule,
/// if the underlying OS scheduler call fails, or if the opt-out sentinel could not be cleared.
pub fn install(exe: &Path, state_dir: &Path) -> Result<(), BrokerError> {
    install_with(
        exe,
        state_dir,
        crate::secure::path_is_privileged_owned,
        imp::install,
    )
}

/// [`install`] factored over its two OS boundaries — the privilege check on `exe`'s directory and the
/// actual OS registration — so the refusal guard is unit-testable without a privileged runner or a
/// real scheduler write.
///
/// The guard runs FIRST: the schedule is registered only from a privileged-owned install root, so a
/// later writer of that directory cannot swap the binary this SYSTEM/root daily task runs.
fn install_with(
    exe: &Path,
    state_dir: &Path,
    is_privileged: impl Fn(&Path) -> bool,
    register: impl FnOnce(&Path) -> Result<(), BrokerError>,
) -> Result<(), BrokerError> {
    refuse_unprivileged_exe_dir(exe, is_privileged)?;
    register(exe)?;
    crate::optout::clear_opted_out(state_dir)
}

/// Refuse to register a SYSTEM/root daily schedule for a binary whose containing directory is NOT
/// privileged-owned (dig_ecosystem#2334, the §565 "privileged artifact whose path is user-controlled"
/// class).
///
/// The daily task runs `exe` as SYSTEM/root forever with no further prompt. If the directory holding
/// `exe` is user-writable (a portable / user-directory install), one UAC/sudo approval becomes a
/// PERMANENT elevated foothold: whoever can later write that directory replaces the binary, and the
/// task runs the replacement elevated. So registration is allowed ONLY from a privileged-owned install
/// root — the ownership of the DIRECTORY, checked via the injected `is_privileged` (production:
/// [`crate::secure::path_is_privileged_owned`]).
///
/// `is_privileged` is injected so the decision is deterministically testable without depending on the
/// test runner's uid or filesystem ownership.
///
/// # Errors
///
/// [`BrokerError::Io`] if `exe` has no parent directory, or if that directory is not privileged-owned.
fn refuse_unprivileged_exe_dir(
    exe: &Path,
    is_privileged: impl Fn(&Path) -> bool,
) -> Result<(), BrokerError> {
    let _ = (exe, is_privileged); // RED: guard not yet wired — proves the tests below are load-bearing
    Ok(())
}

/// Remove the daily scheduler artifact and RECORD a deliberate opt-out. Idempotent: removing an
/// already-absent schedule succeeds.
///
/// The opt-out sentinel ([`crate::optout`]) is what lets an always-on driver (dig-node) tell an
/// ACCIDENTAL deletion — which it re-arms — from this DELIBERATE uninstall, which it respects.
///
/// **The intent is recorded BEFORE the removal, and rescinded if the removal fails**
/// (dig_ecosystem#1822). Writing it afterwards left a window in which the task was already gone and
/// no marker existed yet: any failure of the marker write — and it needs elevation, so it can fail —
/// produced "schedule absent, no opt-out", which is EXACTLY the signature of the defect this ordering
/// makes diagnosable. With the record first, that state can only ever mean something removed the task
/// without going through this function, so it is a usable discriminator rather than an ambiguous one.
/// The reverse window is harmless: a marker with the task still present merely suppresses the
/// self-heal until the next `install` clears it, and never removes anything.
///
/// # Errors
///
/// [`BrokerError::Io`] if the caller lacks privilege, the opt-out sentinel could not be written, or
/// the underlying OS call fails for a reason other than "already absent".
pub fn uninstall(state_dir: &Path) -> Result<(), BrokerError> {
    uninstall_recording_intent_first(&StateDirOptOut(state_dir), imp::uninstall)
}

/// The deliberate-opt-out ledger [`uninstall`] writes through — injected so the ORDERING is
/// unit-testable on every OS without the elevation a real marker write demands (writing one claims
/// privileged ownership, [`crate::optout::set_opted_out`]).
trait OptOutLedger {
    /// Record that the operator deliberately wants no daily schedule.
    fn record(&self) -> Result<(), BrokerError>;
    /// Withdraw a record that turned out not to describe what happened.
    fn rescind(&self) -> Result<(), BrokerError>;
}

/// The production ledger: the opt-out sentinel inside the beacon's state directory.
struct StateDirOptOut<'a>(&'a Path);

impl OptOutLedger for StateDirOptOut<'_> {
    fn record(&self) -> Result<(), BrokerError> {
        crate::optout::set_opted_out(self.0)
    }
    fn rescind(&self) -> Result<(), BrokerError> {
        crate::optout::clear_opted_out(self.0)
    }
}

/// Record the opt-out, then remove the artifact — rescinding the record if the removal fails, so the
/// two never disagree about whether the operator asked for this (see [`uninstall`]).
///
/// A failure to rescind is deliberately not propagated over the removal error it followed: the
/// removal error is the one the caller must act on, and the leftover marker is the safe residue (it
/// suppresses a re-arm of a schedule that is still there, which the next `install` clears).
fn uninstall_recording_intent_first(
    ledger: &dyn OptOutLedger,
    remove: impl FnOnce() -> Result<(), BrokerError>,
) -> Result<(), BrokerError> {
    ledger.record()?;
    remove().inspect_err(|_| {
        let _ = ledger.rescind();
    })
}

/// Report whether the daily schedule is currently registered.
///
/// # Errors
///
/// [`BrokerError::Io`] if the OS could not be queried.
pub fn status() -> Result<ScheduleStatus, BrokerError> {
    imp::status()
}

/// Ensure the daily schedule is registered, SELF-HEALING a provably-absent one (#546).
///
/// This is the fix for the #1 "beacon never updates" cause: the daily SYSTEM/root task was
/// registered exactly ONCE by the installer, and no pass ever re-registered it — so the moment the
/// task went missing, auto-updates were permanently dead. Every `run`/`check --now` pass now calls
/// this, so a beacon that runs (elevated) for ANY reason resurrects its own daily wake.
///
/// Idempotent and conservative:
/// - a deliberate OPT-OUT ([`crate::optout`]) → left untouched ([`EnsureAction::SuppressedByOptOut`]):
///   an operator who ran `schedule uninstall` is never fought (#584). Checked FIRST, so an opted-out
///   ensure never even probes the OS scheduler.
/// - [`SchedulePresence::Registered`] → left untouched ([`EnsureAction::AlreadyRegistered`]).
/// - [`SchedulePresence::Unknown`] → left untouched ([`EnsureAction::LeftUnknown`]): a task whose
///   presence can't be read (e.g. access-denied) is NEVER recreated, or we'd risk clobbering a
///   present-but-unreadable one.
/// - [`SchedulePresence::Absent`] → (re-)registered ([`EnsureAction::Reregistered`]).
///
/// # Errors
///
/// [`BrokerError`] if the OS status probe fails outright, or — only when re-registering — if
/// registration fails (e.g. the caller is not elevated: registering a SYSTEM/root schedule is a
/// privileged act, §8.4). The caller (`Broker::run_once_with_feed`) treats such a failure as
/// best-effort and non-fatal.
pub fn ensure(exe: &Path, state_dir: &Path) -> Result<EnsureAction, BrokerError> {
    ensure_with(
        exe,
        state_dir,
        || Ok(imp::status()?.presence),
        crate::secure::path_is_privileged_owned,
        imp::install,
    )
}

/// [`ensure`] factored over its OS boundaries — the presence probe, the privilege check, and the OS
/// registration — so the self-heal DECISION and its re-register guard are unit-testable without an
/// elevated runner or a real scheduler.
///
/// The re-register branch is guarded exactly like [`install`]: a self-heal that would re-register from
/// a non-privileged-owned directory REFUSES and surfaces the error rather than silently proceeding — a
/// self-heal that cannot safely re-register must report, not manufacture the very foothold #2334 fixes.
fn ensure_with(
    exe: &Path,
    state_dir: &Path,
    presence: impl FnOnce() -> Result<SchedulePresence, BrokerError>,
    is_privileged: impl Fn(&Path) -> bool,
    register: impl FnOnce(&Path) -> Result<(), BrokerError>,
) -> Result<EnsureAction, BrokerError> {
    if crate::optout::is_opted_out(state_dir) {
        return Ok(EnsureAction::SuppressedByOptOut);
    }
    let action = ensure_decision(presence()?);
    if action == EnsureAction::Reregistered {
        refuse_unprivileged_exe_dir(exe, is_privileged)?;
        register(exe)?;
    }
    Ok(action)
}

/// The pure decision [`ensure`] makes from a presence reading (AFTER the opt-out short-circuit) —
/// split out so every branch is exercised deterministically without touching the OS.
#[must_use]
fn ensure_decision(presence: SchedulePresence) -> EnsureAction {
    match presence {
        SchedulePresence::Registered => EnsureAction::AlreadyRegistered,
        SchedulePresence::Unknown => EnsureAction::LeftUnknown,
        SchedulePresence::Absent => EnsureAction::Reregistered,
    }
}

/// Classify a `schtasks /Query` outcome into a [`ScheduleStatus`] (#546, #2323).
///
/// Exit 0 (the task printed) is [`SchedulePresence::Registered`]. A non-zero exit happens for three
/// very different reasons the pre-#546 code conflated into a single "not installed":
/// - **access-denied** — "ERROR: Access is denied." (`0x80070005`), e.g. an unprivileged
///   `schedule status` against the SYSTEM task, or its ACL-hardened definition file → [`Unknown`];
/// - **not-visible when unprivileged** — an unelevated query for a task inside the `\DIG\` folder
///   fails with "ERROR: The system cannot find the path specified." because the folder itself is not
///   visible to a non-elevated user. From `schtasks` stderr alone, unprivileged, this is
///   INDISTINGUISHABLE from a genuinely absent task, so it must NOT resolve to [`Absent`] → [`Unknown`];
/// - **provably absent** — "ERROR: The system cannot find the file specified." (`0x80070002`) or
///   "The specified task name ... does not exist" (`0x8004131F`), seen from an ELEVATED query that
///   CAN read the `\DIG\` folder → [`Absent`].
///
/// The elevation gate is the #2323 fix: only an ELEVATED query can honestly report [`Absent`]
/// (the caller could actually see the folder and the task was not there), which is exactly what the
/// self-heal ([`ensure`]) and idempotent [`uninstall`] rely on — both run elevated, so their
/// behaviour is unchanged. An UNPRIVILEGED failure that is not a recognized access-denied signal is
/// [`Unknown`], never [`Absent`], because the unprivileged query cannot tell the two apart.
///
/// Pure string logic with an injected `is_elevated` bool, so it is unit-testable on every target.
///
/// [`Unknown`]: SchedulePresence::Unknown
/// [`Absent`]: SchedulePresence::Absent
/// [`Registered`]: SchedulePresence::Registered
#[cfg_attr(not(windows), allow(dead_code))]
fn classify_query(success: bool, stderr: &str, is_elevated: bool) -> ScheduleStatus {
    use content::WINDOWS_TASK_PATH;

    if success {
        return ScheduleStatus::registered(format!("registered at {WINDOWS_TASK_PATH}"));
    }
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("access is denied") || lower.contains("0x80070005") {
        return ScheduleStatus::unknown(format!(
            "cannot determine whether {WINDOWS_TASK_PATH} is registered (access denied); \
             re-run elevated to read it"
        ));
    }
    if !is_elevated {
        return ScheduleStatus::unknown(format!(
            "cannot determine whether {WINDOWS_TASK_PATH} is registered without elevation — the \
             unprivileged query cannot distinguish an absent task from one it may not read; \
             re-run elevated, or: schtasks /Query /TN {WINDOWS_TASK_PATH}"
        ));
    }
    ScheduleStatus::absent(format!("no task registered at {WINDOWS_TASK_PATH}"))
}

// ---------------------------------------- Windows ----------------------------------------------

#[cfg(windows)]
mod imp {
    //! ## The task store belongs to Task Scheduler (dig_ecosystem#1822)
    //!
    //! Everything under `%SystemRoot%\System32\Tasks` — the definition files AND the folders that
    //! hold them — is Task Scheduler's own on-disk store, and the AUTHORITATIVE copy of each task's
    //! security descriptor lives beside it in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
    //! Schedule\TaskCache`. The service cross-checks the two and treats a definition whose on-disk SD
    //! no longer matches as tampered-with (`0x80041321`), DISCARDING the task from the tree — which
    //! takes `\DIG`, its only child, with it. A privileged write into that store is therefore not
    //! belt-and-suspenders hardening; it is a way to delete your own schedule.
    //!
    //! So this module registers and removes tasks THROUGH `schtasks` and makes no other write to the
    //! store: no `icacls` over a definition file, no `remove_dir` of a task folder. The Admin/SYSTEM
    //! WRITE bar of SPEC §9.3 is already met by the OS default DACL, which grants Administrators and
    //! SYSTEM Full Control and every other identity READ ONLY (verified against a live Windows 11
    //! task store and asserted by
    //! `tests/scheduler.rs::the_task_definition_file_is_not_writable_by_an_unprivileged_identity`).
    //! Read access is not a concern: `schtasks /Query /XML` prints any task's whole definition to any
    //! user, so nothing is disclosed by a readable definition file.
    //!
    //! Unix is unaffected — a systemd unit / launchd plist is the beacon's OWN file in a root-owned
    //! directory, so writing it root-owned mode `0644` remains correct.

    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::content::{windows_task_xml, JITTER_WINDOW, WINDOWS_TASK_PATH};
    use super::{SchedulePresence, ScheduleStatus};
    use crate::elevation::require_elevated;
    use crate::error::BrokerError;
    use crate::install::trusted_absolute;
    use crate::proc::HideConsole;

    /// The absolute, trusted path to `schtasks.exe` — never a bare name resolved through `PATH`.
    fn schtasks() -> Result<PathBuf, BrokerError> {
        let system_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("windir"))
            .ok_or_else(|| BrokerError::Io("neither %SystemRoot% nor %windir% is set".into()))?;
        trusted_absolute(
            PathBuf::from(system_root)
                .join("System32")
                .join("schtasks.exe"),
        )
        .map_err(BrokerError::Io)
    }

    pub(super) fn install(exe: &Path) -> Result<(), BrokerError> {
        require_elevated()?;
        let xml = windows_task_xml(exe, JITTER_WINDOW);
        let tmp = std::env::temp_dir().join("dig-updater-task.xml");
        // `schtasks /XML` requires the file to genuinely BE UTF-16LE with a byte-order mark — it
        // rejects a well-formed UTF-8 file with "unable to switch the encoding" even though the
        // declaration says so (confirmed live on a Windows runner); this matches the encoding
        // `windows_task_xml`'s prolog declares, so declaration and bytes agree.
        std::fs::write(&tmp, utf16le_with_bom(&xml)).map_err(|e| BrokerError::Io(e.to_string()))?;

        let status = Command::new(schtasks()?)
            .args(["/Create", "/TN", WINDOWS_TASK_PATH, "/XML"])
            .arg(&tmp)
            .arg("/F")
            .hide_console()
            .output()
            .map_err(|e| BrokerError::Io(format!("could not run schtasks: {e}")))?;
        let _ = std::fs::remove_file(&tmp);
        if !status.status.success() {
            return Err(BrokerError::Io(format!(
                "schtasks /Create failed: {}",
                String::from_utf8_lossy(&status.stderr).trim()
            )));
        }

        // NOTHING follows the registration. In particular the definition file's security descriptor
        // is Task Scheduler's, and the beacon MUST NOT touch it — see this module's Windows note.
        Ok(())
    }

    pub(super) fn uninstall() -> Result<(), BrokerError> {
        require_elevated()?;
        let output = Command::new(schtasks()?)
            .args(["/Delete", "/TN", WINDOWS_TASK_PATH, "/F"])
            .hide_console()
            .output()
            .map_err(|e| BrokerError::Io(format!("could not run schtasks: {e}")))?;
        if output.status.success() {
            return Ok(());
        }
        // Idempotent: deleting an already-absent task is success, not an error. Only a PROVABLY
        // absent task counts — an access-denied query (`Unknown`) means we could neither delete nor
        // confirm removal, which is a real failure, not a benign no-op.
        if status()?.presence == SchedulePresence::Absent {
            return Ok(());
        }
        Err(BrokerError::Io(format!(
            "schtasks /Delete failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    pub(super) fn status() -> Result<ScheduleStatus, BrokerError> {
        let output = Command::new(schtasks()?)
            .args(["/Query", "/TN", WINDOWS_TASK_PATH])
            .hide_console()
            .output()
            .map_err(|e| BrokerError::Io(format!("could not run schtasks: {e}")))?;
        Ok(super::classify_query(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
            crate::elevation::is_elevated(),
        ))
    }

    /// Encode `text` as UTF-16LE bytes with a leading byte-order mark — the exact form
    /// `schtasks /XML` requires (see [`install`]'s comment on why a plain UTF-8 file is rejected).
    fn utf16le_with_bom(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFFu8, 0xFE]; // BOM, little-endian
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[cfg(test)]
    mod tests {
        use super::utf16le_with_bom;

        #[test]
        fn utf16le_with_bom_starts_with_the_little_endian_bom() {
            let bytes = utf16le_with_bom("hi");
            assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        }

        #[test]
        fn utf16le_with_bom_encodes_ascii_as_two_bytes_per_char() {
            // 'h' = 0x0068, 'i' = 0x0069, little-endian.
            let bytes = utf16le_with_bom("hi");
            assert_eq!(&bytes[2..], &[0x68, 0x00, 0x69, 0x00]);
        }

        #[test]
        fn utf16le_with_bom_round_trips_through_string_from_utf16() {
            let original = "<Task>\u{2764}</Task>"; // include a non-ASCII code point
            let bytes = utf16le_with_bom(original);
            let units: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            assert_eq!(String::from_utf16(&units).unwrap(), original);
        }
    }
}

// ------------------------------------------ Linux ------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::content::{
        systemd_service_unit, systemd_timer_unit, JITTER_WINDOW, SYSTEMD_UNIT_NAME,
    };
    use super::ScheduleStatus;
    use crate::elevation::require_elevated;
    use crate::error::BrokerError;
    use crate::install::first_trusted;
    use crate::proc::HideConsole;

    const UNIT_DIR: &str = "/etc/systemd/system";

    fn service_path() -> PathBuf {
        PathBuf::from(UNIT_DIR).join(format!("{SYSTEMD_UNIT_NAME}.service"))
    }
    fn timer_path() -> PathBuf {
        PathBuf::from(UNIT_DIR).join(format!("{SYSTEMD_UNIT_NAME}.timer"))
    }
    fn timer_unit_name() -> String {
        format!("{SYSTEMD_UNIT_NAME}.timer")
    }

    fn systemctl() -> Result<PathBuf, BrokerError> {
        first_trusted(&["/usr/bin/systemctl", "/bin/systemctl"]).map_err(BrokerError::Io)
    }

    /// Write a unit file root-owned, mode `0644` — world-readable (so `systemctl status`/any user
    /// can inspect it, the systemd convention), root-writable only (enforced by `/etc/systemd/system`
    /// itself being a root-owned, non-world-writable directory).
    fn write_unit(path: &Path, content: &str) -> Result<(), BrokerError> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, content).map_err(|e| BrokerError::Io(e.to_string()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| BrokerError::Io(e.to_string()))
    }

    fn run(systemctl: &Path, args: &[&str]) -> Result<std::process::Output, BrokerError> {
        Command::new(systemctl)
            .args(args)
            .hide_console()
            .output()
            .map_err(|e| BrokerError::Io(format!("could not run systemctl: {e}")))
    }

    pub(super) fn install(exe: &Path) -> Result<(), BrokerError> {
        require_elevated()?;
        write_unit(&service_path(), &systemd_service_unit(exe))?;
        write_unit(&timer_path(), &systemd_timer_unit(JITTER_WINDOW))?;
        let systemctl = systemctl()?;
        let reload = run(&systemctl, &["daemon-reload"])?;
        if !reload.status.success() {
            return Err(BrokerError::Io(format!(
                "systemctl daemon-reload failed: {}",
                String::from_utf8_lossy(&reload.stderr).trim()
            )));
        }
        let enable = run(&systemctl, &["enable", "--now", &timer_unit_name()])?;
        if !enable.status.success() {
            return Err(BrokerError::Io(format!(
                "systemctl enable --now {} failed: {}",
                timer_unit_name(),
                String::from_utf8_lossy(&enable.stderr).trim()
            )));
        }
        Ok(())
    }

    pub(super) fn uninstall() -> Result<(), BrokerError> {
        require_elevated()?;
        let systemctl = systemctl()?;
        // Best-effort: disabling an already-absent/disabled timer is not fatal — the goal is a
        // clean removal either way.
        let _ = run(&systemctl, &["disable", "--now", &timer_unit_name()]);
        for path in [service_path(), timer_path()] {
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| BrokerError::Io(e.to_string()))?;
            }
        }
        let reload = run(&systemctl, &["daemon-reload"])?;
        if !reload.status.success() {
            return Err(BrokerError::Io(format!(
                "systemctl daemon-reload failed: {}",
                String::from_utf8_lossy(&reload.stderr).trim()
            )));
        }
        Ok(())
    }

    pub(super) fn status() -> Result<ScheduleStatus, BrokerError> {
        if !service_path().exists() || !timer_path().exists() {
            return Ok(ScheduleStatus::absent(format!(
                "no unit files at {UNIT_DIR}/{SYSTEMD_UNIT_NAME}.{{service,timer}}"
            )));
        }
        let systemctl = systemctl()?;
        let enabled = run(&systemctl, &["is-enabled", &timer_unit_name()])?;
        Ok(if enabled.status.success() {
            ScheduleStatus::registered(format!("{} is enabled", timer_unit_name()))
        } else {
            ScheduleStatus::absent(format!(
                "unit files present but {} is not enabled",
                timer_unit_name()
            ))
        })
    }
}

// ------------------------------------------ macOS ------------------------------------------------

#[cfg(target_os = "macos")]
mod imp {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::content::{launchd_jitter, launchd_plist, LAUNCHD_LABEL};
    use super::ScheduleStatus;
    use crate::elevation::require_elevated;
    use crate::error::BrokerError;
    use crate::install::first_trusted;
    use crate::proc::HideConsole;

    fn plist_path() -> PathBuf {
        PathBuf::from("/Library/LaunchDaemons").join(format!("{LAUNCHD_LABEL}.plist"))
    }

    fn launchctl() -> Result<PathBuf, BrokerError> {
        first_trusted(&["/bin/launchctl", "/usr/bin/launchctl"]).map_err(BrokerError::Io)
    }

    pub(super) fn install(exe: &Path) -> Result<(), BrokerError> {
        require_elevated()?;
        // `launchctl bootstrap` REFUSES an already-bootstrapped label (idempotent re-install —
        // e.g. a re-run installer — would otherwise error), so clear any prior registration
        // first, exactly like dig-installer's own dig-dns LaunchDaemon install does: a fresh
        // install always starts from a clean slate rather than reconfiguring in place.
        bootout_and_remove_plist();

        let entropy = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let (hour, minute) = launchd_jitter(entropy);
        let plist = launchd_plist(exe, hour, minute);

        use std::os::unix::fs::PermissionsExt;
        let path = plist_path();
        std::fs::write(&path, &plist).map_err(|e| BrokerError::Io(e.to_string()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| BrokerError::Io(e.to_string()))?;

        let output = Command::new(launchctl()?)
            .args(["bootstrap", "system"])
            .arg(&path)
            .hide_console()
            .output()
            .map_err(|e| BrokerError::Io(format!("could not run launchctl: {e}")))?;
        if !output.status.success() {
            return Err(BrokerError::Io(format!(
                "launchctl bootstrap failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    pub(super) fn uninstall() -> Result<(), BrokerError> {
        require_elevated()?;
        bootout_and_remove_plist();
        Ok(())
    }

    /// Best-effort: `bootout` an existing registration and delete its plist. An already-absent
    /// registration is a no-op — this is the shared clean-slate step both `install` (before
    /// re-bootstrapping) and `uninstall` need.
    fn bootout_and_remove_plist() {
        if let Ok(launchctl) = launchctl() {
            let _ = Command::new(launchctl)
                .args(["bootout", &format!("system/{LAUNCHD_LABEL}")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .hide_console()
                .status();
        }
        let _ = std::fs::remove_file(plist_path());
    }

    pub(super) fn status() -> Result<ScheduleStatus, BrokerError> {
        let registered = Command::new(launchctl()?)
            .args(["print", &format!("system/{LAUNCHD_LABEL}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .hide_console()
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Ok(if registered {
            ScheduleStatus::registered(format!("{LAUNCHD_LABEL} is loaded"))
        } else {
            ScheduleStatus::absent(format!("{LAUNCHD_LABEL} is not loaded"))
        })
    }
}

// ------------------------------------- unsupported OS fallback -----------------------------------

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod imp {
    use std::path::Path;

    use super::ScheduleStatus;
    use crate::error::BrokerError;

    pub(super) fn install(_exe: &Path) -> Result<(), BrokerError> {
        Err(BrokerError::Unimplemented(
            "scheduler artifact (unsupported OS)",
        ))
    }
    pub(super) fn uninstall() -> Result<(), BrokerError> {
        Err(BrokerError::Unimplemented(
            "scheduler artifact (unsupported OS)",
        ))
    }
    pub(super) fn status() -> Result<ScheduleStatus, BrokerError> {
        Err(BrokerError::Unimplemented(
            "scheduler artifact (unsupported OS)",
        ))
    }
}

// -------------------- portable self-heal DECISION tests (every OS) -------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    /// What a test observed the ledger being asked to do, in order.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LedgerCall {
        Record,
        Rescind,
    }

    /// A recording [`OptOutLedger`] whose `record` can be made to FAIL — the fixture that separates
    /// "the marker write failed" from "the removal failed", which is the whole point of the ordering.
    struct RecordingLedger {
        calls: RefCell<Vec<LedgerCall>>,
        record_fails: bool,
    }

    impl RecordingLedger {
        fn working() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                record_fails: false,
            }
        }
        fn that_cannot_record() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                record_fails: true,
            }
        }
        fn calls(&self) -> Vec<LedgerCall> {
            self.calls.borrow().clone()
        }
    }

    impl OptOutLedger for RecordingLedger {
        fn record(&self) -> Result<(), BrokerError> {
            self.calls.borrow_mut().push(LedgerCall::Record);
            if self.record_fails {
                return Err(BrokerError::Io(
                    "not elevated enough to claim ownership".into(),
                ));
            }
            Ok(())
        }
        fn rescind(&self) -> Result<(), BrokerError> {
            self.calls.borrow_mut().push(LedgerCall::Rescind);
            Ok(())
        }
    }

    #[test]
    fn uninstall_records_the_optout_before_it_removes_anything() {
        // dig_ecosystem#1822: the marker must already exist by the time the artifact can vanish, so
        // "absent schedule, no marker" can never be produced by a half-completed uninstall. Asserting
        // the ORDER is what pins this — asserting only that both happened would pass on the old
        // remove-then-record code, which is precisely the ordering being fixed.
        let ledger = RecordingLedger::working();
        let removed = RefCell::new(false);
        uninstall_recording_intent_first(&ledger, || {
            assert_eq!(
                ledger.calls(),
                vec![LedgerCall::Record],
                "the opt-out must already be recorded when the removal runs"
            );
            *removed.borrow_mut() = true;
            Ok(())
        })
        .expect("a successful removal after a successful record");

        assert!(*removed.borrow(), "the artifact was removed");
        assert_eq!(
            ledger.calls(),
            vec![LedgerCall::Record],
            "a successful uninstall never rescinds its own record"
        );
    }

    #[test]
    fn uninstall_rescinds_the_optout_when_the_removal_is_the_step_that_fails() {
        // The other half of the ordering: a recorded intent that turned out not to have happened must
        // be withdrawn, or a failed uninstall would leave auto-updates suppressed for a schedule that
        // is still registered — the self-heal silenced by a removal that never occurred.
        let ledger = RecordingLedger::working();
        let err = uninstall_recording_intent_first(&ledger, || {
            Err(BrokerError::Io(
                "schtasks /Delete failed: access is denied".into(),
            ))
        })
        .expect_err("the removal failure reaches the caller");

        assert!(
            err.to_string().contains("schtasks"),
            "the REMOVAL error is what the caller must act on, not a rescind error: {err}"
        );
        assert_eq!(
            ledger.calls(),
            vec![LedgerCall::Record, LedgerCall::Rescind]
        );
    }

    #[test]
    fn uninstall_removes_nothing_when_the_optout_cannot_be_recorded() {
        // Fail-closed on the marker: if the deliberate intent cannot be written down, the schedule
        // stays. Removing it anyway would manufacture the exact undiagnosable state — task gone, no
        // marker — that this ordering exists to make impossible.
        let ledger = RecordingLedger::that_cannot_record();
        let err = uninstall_recording_intent_first(&ledger, || {
            panic!("the removal must not run when the opt-out could not be recorded")
        })
        .expect_err("an unrecordable opt-out fails the uninstall");

        assert!(err.to_string().contains("ownership"), "{err}");
        assert_eq!(ledger.calls(), vec![LedgerCall::Record]);
    }

    #[test]
    fn classify_query_reports_a_successful_query_as_registered() {
        // Elevation is irrelevant on success: the task printed, so it is registered either way.
        assert_eq!(
            classify_query(true, "", false).presence,
            SchedulePresence::Registered
        );
        assert_eq!(
            classify_query(true, "", true).presence,
            SchedulePresence::Registered
        );
    }

    #[test]
    fn classify_query_reports_access_denied_as_unknown_not_absent() {
        // The #546 fix: a locked-but-present task must NOT masquerade as absent — recognized by the
        // English message and/or the 0x80070005 code, regardless of elevation.
        for is_elevated in [false, true] {
            assert_eq!(
                classify_query(false, "ERROR: Access is denied.", is_elevated).presence,
                SchedulePresence::Unknown
            );
            assert_eq!(
                classify_query(false, "some prefix 0x80070005 suffix", is_elevated).presence,
                SchedulePresence::Unknown
            );
        }
    }

    #[test]
    fn classify_query_unprivileged_path_not_found_is_unknown_not_absent() {
        // The #2323 fix: run UNPRIVILEGED, an unelevated `schtasks /Query /TN \DIG\dig-updater`
        // fails with "the system cannot find the path specified" because the `\DIG\` folder is not
        // visible to a non-elevated user — which is INDISTINGUISHABLE from a genuinely absent task.
        // The probe must NOT resolve to Absent, or `schedule status` states the opposite of the
        // truth on a machine where the task IS registered.
        let path_not_found = "ERROR: The system cannot find the path specified.";
        assert_eq!(
            classify_query(false, path_not_found, /* is_elevated = */ false).presence,
            SchedulePresence::Unknown,
        );
        // Any other unprivileged failure is equally undeterminable → Unknown, never Absent.
        assert_eq!(
            classify_query(false, "ERROR: something unexpected happened", false).presence,
            SchedulePresence::Unknown,
        );
    }

    #[test]
    fn classify_query_elevated_not_found_is_absent_preserving_self_heal() {
        // ELEVATED, the query CAN read the `\DIG\` folder, so a not-found is PROVABLY absent — the
        // one state the self-heal ([`ensure`]) re-registers from and idempotent uninstall relies on.
        let file_not_found = "ERROR: The system cannot find the file specified.";
        let no_such_task = "ERROR: The specified task name \"\\DIG\\dig-updater\" \
                            does not exist in the system.";
        assert_eq!(
            classify_query(false, file_not_found, /* is_elevated = */ true).presence,
            SchedulePresence::Absent
        );
        assert_eq!(
            classify_query(false, no_such_task, true).presence,
            SchedulePresence::Absent
        );
        // An unrecognized (e.g. localized) failure, seen ELEVATED, still defaults to Absent so the
        // self-heal fires for an unfamiliar not-found message.
        assert_eq!(
            classify_query(false, "ERROR: something unexpected happened", true).presence,
            SchedulePresence::Absent
        );
    }

    #[test]
    fn ensure_re_registers_only_a_provably_absent_schedule() {
        // The heart of #546: a provably-absent schedule self-heals; a registered one is left
        // alone; and — the safety property — a presence that can't be read is NEVER recreated.
        assert_eq!(
            ensure_decision(SchedulePresence::Absent),
            EnsureAction::Reregistered
        );
        assert_eq!(
            ensure_decision(SchedulePresence::Registered),
            EnsureAction::AlreadyRegistered
        );
        assert_eq!(
            ensure_decision(SchedulePresence::Unknown),
            EnsureAction::LeftUnknown,
        );
    }

    #[test]
    #[ignore = "requires Administrator/root to write a privileged-owned opt-out marker — run via \
                `-- --ignored` in the elevated scheduler CI job"]
    fn ensure_short_circuits_to_suppressed_when_a_privileged_opt_out_marker_is_present() {
        // #584: a DELIBERATE `schedule uninstall` writes a PRIVILEGED-OWNED opt-out marker; `ensure`
        // must honor it and return WITHOUT touching the OS scheduler. The short-circuit only fires
        // for a privileged-owned marker (the loop-security un-forgeability fix), which requires
        // being elevated to produce — so this runs in the elevated CI job (Windows Administrator /
        // Unix sudo), alongside the scheduler integration tests.
        let state_dir = tempfile::tempdir().expect("state dir");
        crate::optout::set_opted_out(state_dir.path()).expect("write the opt-out marker");
        let exe = std::env::current_exe().expect("test exe");
        assert_eq!(
            ensure(&exe, state_dir.path()).expect("ensure honors the opt-out without an OS probe"),
            EnsureAction::SuppressedByOptOut
        );
    }

    // ---------------- #2334: refuse to register from a non-privileged-owned dir -----------------

    /// A canonical exe path with a parent directory, for the guard tests.
    fn exe_with_parent() -> PathBuf {
        PathBuf::from("/opt/dig/bin/dig-updater")
    }

    #[test]
    fn refuse_unprivileged_exe_dir_rejects_a_user_writable_dir_and_names_it() {
        // #2334: the daily task runs `exe` as SYSTEM/root forever. If its directory is user-writable,
        // one elevation approval becomes a permanent foothold. The guard must REFUSE and name the
        // exact directory so the operator can see which install root was rejected.
        let exe = exe_with_parent();
        let err = refuse_unprivileged_exe_dir(&exe, |_dir| false)
            .expect_err("a non-privileged-owned exe directory must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("/opt/dig/bin"),
            "the refusal must name the offending directory, got: {msg}"
        );
        assert!(
            msg.contains("foothold"),
            "the refusal must explain WHY (the elevated-foothold risk), got: {msg}"
        );
    }

    #[test]
    fn refuse_unprivileged_exe_dir_checks_the_directory_not_the_binary() {
        // The property being guarded is DIRECTORY ownership — a later writer of the dir swaps the
        // binary. The predicate must be handed the parent dir, never the exe itself (a fix that
        // checked the binary's own path would satisfy an outcome-only test but miss the real threat).
        let exe = exe_with_parent();
        let seen = RefCell::new(Vec::new());
        let _ = refuse_unprivileged_exe_dir(&exe, |dir| {
            seen.borrow_mut().push(dir.to_path_buf());
            true
        });
        assert_eq!(
            seen.borrow().as_slice(),
            &[PathBuf::from("/opt/dig/bin")],
            "the guard must check the exe's PARENT directory, not the exe path"
        );
    }

    #[test]
    fn refuse_unprivileged_exe_dir_allows_a_privileged_owned_dir() {
        refuse_unprivileged_exe_dir(&exe_with_parent(), |_dir| true)
            .expect("a privileged-owned install root must be allowed");
    }

    #[test]
    fn refuse_unprivileged_exe_dir_errors_legibly_when_exe_has_no_parent() {
        // A root path has no parent directory to verify — refuse legibly rather than panic/unwrap.
        let err = refuse_unprivileged_exe_dir(Path::new("/"), |_dir| true)
            .expect_err("a parentless exe path cannot be verified and must be refused");
        assert!(
            err.to_string().contains("parent"),
            "the refusal must explain the missing parent directory, got: {err}"
        );
    }

    #[test]
    fn install_refuses_a_non_privileged_owned_exe_dir_before_registering() {
        // Path 1 (the CLI wrapper): `install` must run the guard BEFORE `imp::install`, so a
        // non-privileged-owned install root never reaches the OS registration at all.
        let state = tempfile::tempdir().expect("state dir");
        let registered = RefCell::new(false);
        let err = install_with(
            &exe_with_parent(),
            state.path(),
            |_dir| false,
            |_exe| {
                *registered.borrow_mut() = true;
                Ok(())
            },
        )
        .expect_err("install must refuse a non-privileged-owned exe dir");
        assert!(err.to_string().contains("foothold"), "{err}");
        assert!(
            !*registered.borrow(),
            "the OS registration must NOT run when the guard refuses"
        );
    }

    #[test]
    fn install_proceeds_to_register_from_a_privileged_owned_dir() {
        let state = tempfile::tempdir().expect("state dir");
        let registered = RefCell::new(false);
        install_with(
            &exe_with_parent(),
            state.path(),
            |_dir| true,
            |_exe| {
                *registered.borrow_mut() = true;
                Ok(())
            },
        )
        .expect("a privileged-owned root registers normally");
        assert!(
            *registered.borrow(),
            "registration proceeds on the happy path"
        );
    }

    #[test]
    fn ensure_reregister_refuses_a_non_privileged_owned_exe_dir() {
        // Path 2 (the self-heal): the `Reregistered` branch calls `imp::install` DIRECTLY, so it must
        // carry its own guard or it is a bypass of path 1. A provably-absent schedule whose exe dir is
        // not privileged-owned must REFUSE (surface the error), never silently re-register.
        let state = tempfile::tempdir().expect("state dir");
        let registered = RefCell::new(false);
        let err = ensure_with(
            &exe_with_parent(),
            state.path(),
            || Ok(SchedulePresence::Absent),
            |_dir| false,
            |_exe| {
                *registered.borrow_mut() = true;
                Ok(())
            },
        )
        .expect_err("the self-heal must refuse to re-register from a non-privileged-owned dir");
        assert!(err.to_string().contains("foothold"), "{err}");
        assert!(
            !*registered.borrow(),
            "the self-heal must NOT re-register when the guard refuses"
        );
    }

    #[test]
    fn ensure_reregister_proceeds_from_a_privileged_owned_dir() {
        let state = tempfile::tempdir().expect("state dir");
        let registered = RefCell::new(false);
        let action = ensure_with(
            &exe_with_parent(),
            state.path(),
            || Ok(SchedulePresence::Absent),
            |_dir| true,
            |_exe| {
                *registered.borrow_mut() = true;
                Ok(())
            },
        )
        .expect("a privileged-owned root re-registers normally");
        assert_eq!(action, EnsureAction::Reregistered);
        assert!(
            *registered.borrow(),
            "the self-heal re-registers on the happy path"
        );
    }

    #[test]
    fn ensure_does_not_invoke_the_guard_when_already_registered() {
        // The guard gates ONLY the re-register branch: an already-registered schedule is left
        // untouched and never consults the privilege check (a guard on the non-acting branch would be
        // a spurious refusal of a healthy machine).
        let state = tempfile::tempdir().expect("state dir");
        let guard_consulted = RefCell::new(false);
        let action = ensure_with(
            &exe_with_parent(),
            state.path(),
            || Ok(SchedulePresence::Registered),
            |_dir| {
                *guard_consulted.borrow_mut() = true;
                false
            },
            |_exe| panic!("a registered schedule must not re-register"),
        )
        .expect("an already-registered schedule is left untouched");
        assert_eq!(action, EnsureAction::AlreadyRegistered);
        assert!(
            !*guard_consulted.borrow(),
            "the guard must not run when nothing is being registered"
        );
    }

    #[test]
    fn refuse_unprivileged_exe_dir_with_the_real_check_agrees_with_the_production_predicate() {
        // Integration-flavored: wired to the REAL `path_is_privileged_owned`, the guard's verdict on a
        // real directory must MATCH what the production predicate says about that directory — proving
        // the guard consults the parent dir through the production check, deterministically under ANY
        // runner uid (root CI sees the tempdir as privileged-owned; an unprivileged runner does not).
        let dir = tempfile::tempdir().expect("temp dir");
        let exe = dir.path().join("dig-updater");
        std::fs::write(&exe, b"binary").expect("write a fake exe");

        let dir_is_privileged = crate::secure::path_is_privileged_owned(dir.path());
        let guard = refuse_unprivileged_exe_dir(&exe, crate::secure::path_is_privileged_owned);
        assert_eq!(
            guard.is_ok(),
            dir_is_privileged,
            "the guard must allow iff the production predicate deems the exe's directory \
             privileged-owned"
        );
    }

    #[test]
    fn installed_is_true_only_for_registered_never_for_unknown() {
        assert!(ScheduleStatus::registered("x".into()).installed());
        assert!(!ScheduleStatus::absent("x".into()).installed());
        // An access-denied "can't tell" must NOT read as installed — but also must not read as a
        // confident "absent" to the self-heal (that distinction lives in `presence`).
        assert!(!ScheduleStatus::unknown("x".into()).installed());
    }
}
