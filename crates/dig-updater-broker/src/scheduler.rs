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
    imp::install(exe)?;
    crate::optout::clear_opted_out(state_dir)
}

/// Remove the daily scheduler artifact and RECORD a deliberate opt-out. Idempotent: removing an
/// already-absent schedule succeeds.
///
/// The opt-out sentinel ([`crate::optout`]) is written only AFTER a successful removal, so an
/// always-on driver (dig-node) never re-arms a schedule the operator DELIBERATELY removed — the
/// distinction between an accidental deletion (re-arm) and this deliberate uninstall (respect).
///
/// # Errors
///
/// [`BrokerError::Io`] if the caller lacks privilege, the underlying OS call fails for a reason
/// other than "already absent", or the opt-out sentinel could not be written.
pub fn uninstall(state_dir: &Path) -> Result<(), BrokerError> {
    imp::uninstall()?;
    crate::optout::set_opted_out(state_dir)
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
    if crate::optout::is_opted_out(state_dir) {
        return Ok(EnsureAction::SuppressedByOptOut);
    }
    let action = ensure_decision(imp::status()?.presence);
    if action == EnsureAction::Reregistered {
        imp::install(exe)?;
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

// ---------------------------------------- Windows ----------------------------------------------

#[cfg(windows)]
mod imp {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::content::{windows_task_xml, JITTER_WINDOW, WINDOWS_TASK_PATH};
    use super::{SchedulePresence, ScheduleStatus};
    use crate::elevation::require_elevated;
    use crate::error::BrokerError;
    use crate::install::trusted_absolute;
    use crate::proc::HideConsole;
    use crate::secure::harden_state_dir;

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

    /// Where Task Scheduler stores the registered task's XML definition on disk — hardened
    /// explicitly below as belt-and-suspenders on top of the OS's own default task-store ACLs.
    fn definition_file() -> Result<PathBuf, BrokerError> {
        let system_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("windir"))
            .ok_or_else(|| BrokerError::Io("neither %SystemRoot% nor %windir% is set".into()))?;
        let relative = WINDOWS_TASK_PATH
            .trim_start_matches('\\')
            .replace('\\', "/");
        Ok(PathBuf::from(system_root)
            .join("System32")
            .join("Tasks")
            .join(relative))
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

        // Belt-and-suspenders on top of Task Scheduler's own default task-store ACLs: explicitly
        // restrict the definition file to Administrators + SYSTEM, matching every other guarded
        // path in this crate (SPEC §9.3).
        if let Ok(path) = definition_file() {
            let _ = harden_state_dir(&path);
        }
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
            remove_empty_task_folder();
            return Ok(());
        }
        // Idempotent: deleting an already-absent task is success, not an error. Only a PROVABLY
        // absent task counts — an access-denied query (`Unknown`) means we could neither delete nor
        // confirm removal, which is a real failure, not a benign no-op.
        if status()?.presence == SchedulePresence::Absent {
            remove_empty_task_folder();
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
        Ok(classify_query(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
        ))
    }

    /// Classify a `schtasks /Query` outcome into a [`ScheduleStatus`] (#546).
    ///
    /// Exit 0 (the task printed) is [`SchedulePresence::Registered`]. A non-zero exit happens for two
    /// very different reasons the pre-#546 code conflated into a single "not installed":
    /// - **absent** — "ERROR: The system cannot find the file specified." (`0x80070002`) or "The
    ///   specified task name ... does not exist" (`0x8004131F`);
    /// - **access-denied** — "ERROR: Access is denied." (`0x80070005`), e.g. an unprivileged
    ///   `schedule status` against the SYSTEM task, or its ACL-hardened definition file.
    ///
    /// Only a recognized access-denied signal yields [`SchedulePresence::Unknown`]; every other
    /// failure stays [`SchedulePresence::Absent`], preserving the pre-#546 default so the self-heal
    /// still fires (and status still reads NOT REGISTERED) for the common, possibly-localized
    /// not-found message — while fixing the one dangerous conflation (a locked task looking absent).
    fn classify_query(success: bool, stderr: &str) -> ScheduleStatus {
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
        ScheduleStatus::absent(format!("no task registered at {WINDOWS_TASK_PATH}"))
    }

    /// Best-effort removal of the now-empty `\DIG` Task Scheduler FOLDER after the task itself is
    /// deleted, so an empty folder can't masquerade as a partial install (#546).
    ///
    /// The folder is Task Scheduler's on-disk representation at `%SystemRoot%\System32\Tasks\DIG`;
    /// once `schtasks /Delete` removed the task's definition file, removing its empty parent tidies
    /// up. [`std::fs::remove_dir`] removes an EMPTY directory only — so if any OTHER DIG task lives
    /// under `\DIG` this is a silent no-op (the safe behavior), and a guard restricts it to the
    /// `DIG` subfolder so the `Tasks` root itself is never touched. Never fatal: a leftover empty
    /// folder is cosmetic.
    fn remove_empty_task_folder() {
        let Ok(task_file) = definition_file() else {
            return;
        };
        if let Some(folder) = task_file.parent() {
            if folder.file_name().and_then(|n| n.to_str()) == Some("DIG") {
                let _ = std::fs::remove_dir(folder);
            }
        }
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
        use super::{classify_query, utf16le_with_bom};
        use crate::scheduler::SchedulePresence;

        #[test]
        fn classify_query_reports_a_successful_query_as_registered() {
            assert_eq!(
                classify_query(true, "").presence,
                SchedulePresence::Registered
            );
        }

        #[test]
        fn classify_query_reports_a_not_found_failure_as_absent() {
            // The two shapes schtasks prints for a genuinely missing task.
            let file_not_found = "ERROR: The system cannot find the file specified.";
            let no_such_task = "ERROR: The specified task name \"\\DIG\\dig-updater\" \
                                does not exist in the system.";
            assert_eq!(
                classify_query(false, file_not_found).presence,
                SchedulePresence::Absent
            );
            assert_eq!(
                classify_query(false, no_such_task).presence,
                SchedulePresence::Absent
            );
        }

        #[test]
        fn classify_query_reports_access_denied_as_unknown_not_absent() {
            // The #546 fix: a locked-but-present task must NOT masquerade as absent — recognized
            // by the English message and/or the 0x80070005 code.
            assert_eq!(
                classify_query(false, "ERROR: Access is denied.").presence,
                SchedulePresence::Unknown
            );
            assert_eq!(
                classify_query(false, "some prefix 0x80070005 suffix").presence,
                SchedulePresence::Unknown
            );
        }

        #[test]
        fn classify_query_defaults_an_unrecognized_failure_to_absent() {
            // Preserves the pre-#546 default so the self-heal still fires for an unfamiliar
            // (e.g. localized) not-found message; only recognized access-denied becomes Unknown.
            assert_eq!(
                classify_query(false, "ERROR: something unexpected happened").presence,
                SchedulePresence::Absent
            );
        }

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

    #[test]
    fn installed_is_true_only_for_registered_never_for_unknown() {
        assert!(ScheduleStatus::registered("x".into()).installed());
        assert!(!ScheduleStatus::absent("x".into()).installed());
        // An access-denied "can't tell" must NOT read as installed — but also must not read as a
        // confident "absent" to the self-heal (that distinction lives in `presence`).
        assert!(!ScheduleStatus::unknown("x".into()).installed());
    }
}
