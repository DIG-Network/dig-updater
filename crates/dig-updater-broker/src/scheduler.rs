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

/// Whether the daily schedule is currently registered, and a human detail for `dig-updater
/// schedule status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleStatus {
    /// Is the artifact registered with the OS scheduler right now?
    pub installed: bool,
    /// A human-readable detail (the artifact path/label, or why it is absent).
    pub detail: String,
}

/// Register the daily scheduler artifact that invokes `<exe> run`.
///
/// # Errors
///
/// [`BrokerError::Io`] if the caller lacks the privilege to register a SYSTEM/root-run schedule,
/// or if the underlying OS scheduler call fails.
pub fn install(exe: &Path) -> Result<(), BrokerError> {
    imp::install(exe)
}

/// Remove the daily scheduler artifact. Idempotent: removing an already-absent schedule succeeds.
///
/// # Errors
///
/// [`BrokerError::Io`] if the caller lacks privilege, or the underlying OS call fails for a reason
/// other than "already absent".
pub fn uninstall() -> Result<(), BrokerError> {
    imp::uninstall()
}

/// Report whether the daily schedule is currently registered.
///
/// # Errors
///
/// [`BrokerError::Io`] if the OS could not be queried.
pub fn status() -> Result<ScheduleStatus, BrokerError> {
    imp::status()
}

// ---------------------------------------- Windows ----------------------------------------------

#[cfg(windows)]
mod imp {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use super::content::{windows_task_xml, JITTER_WINDOW, WINDOWS_TASK_PATH};
    use super::ScheduleStatus;
    use crate::error::BrokerError;
    use crate::install::trusted_absolute;
    use crate::secure::harden_state_dir;

    /// Is this process elevated (Administrator)? `net session` succeeds only when elevated — the
    /// same probe dig-relay's own service registration uses, so both repos fail the same way for
    /// the same reason.
    fn is_elevated() -> bool {
        Command::new("net")
            .arg("session")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

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
            .output()
            .map_err(|e| BrokerError::Io(format!("could not run schtasks: {e}")))?;
        if output.status.success() {
            return Ok(());
        }
        // Idempotent: deleting an already-absent task is success, not an error.
        if !status()?.installed {
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
            .output()
            .map_err(|e| BrokerError::Io(format!("could not run schtasks: {e}")))?;
        Ok(if output.status.success() {
            ScheduleStatus {
                installed: true,
                detail: format!("registered at {WINDOWS_TASK_PATH}"),
            }
        } else {
            ScheduleStatus {
                installed: false,
                detail: format!("no task registered at {WINDOWS_TASK_PATH}"),
            }
        })
    }

    fn require_elevated() -> Result<(), BrokerError> {
        if is_elevated() {
            Ok(())
        } else {
            Err(BrokerError::Io(
                "registering the daily schedule requires an elevated (Administrator) console"
                    .into(),
            ))
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
    use crate::error::BrokerError;
    use crate::install::first_trusted;

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
            .output()
            .map_err(|e| BrokerError::Io(format!("could not run systemctl: {e}")))
    }

    pub(super) fn install(exe: &Path) -> Result<(), BrokerError> {
        require_root()?;
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
        require_root()?;
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
            return Ok(ScheduleStatus {
                installed: false,
                detail: format!(
                    "no unit files at {UNIT_DIR}/{SYSTEMD_UNIT_NAME}.{{service,timer}}"
                ),
            });
        }
        let systemctl = systemctl()?;
        let enabled = run(&systemctl, &["is-enabled", &timer_unit_name()])?;
        Ok(if enabled.status.success() {
            ScheduleStatus {
                installed: true,
                detail: format!("{} is enabled", timer_unit_name()),
            }
        } else {
            ScheduleStatus {
                installed: false,
                detail: format!(
                    "unit files present but {} is not enabled",
                    timer_unit_name()
                ),
            }
        })
    }

    fn require_root() -> Result<(), BrokerError> {
        // SAFETY: `geteuid` has no preconditions and is always safe to call.
        if unsafe { libc::geteuid() } == 0 {
            Ok(())
        } else {
            Err(BrokerError::Io(
                "registering the daily schedule requires root".into(),
            ))
        }
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
    use crate::error::BrokerError;
    use crate::install::first_trusted;

    fn plist_path() -> PathBuf {
        PathBuf::from("/Library/LaunchDaemons").join(format!("{LAUNCHD_LABEL}.plist"))
    }

    fn launchctl() -> Result<PathBuf, BrokerError> {
        first_trusted(&["/bin/launchctl", "/usr/bin/launchctl"]).map_err(BrokerError::Io)
    }

    pub(super) fn install(exe: &Path) -> Result<(), BrokerError> {
        require_root()?;
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
        require_root()?;
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
                .status();
        }
        let _ = std::fs::remove_file(plist_path());
    }

    pub(super) fn status() -> Result<ScheduleStatus, BrokerError> {
        let registered = Command::new(launchctl()?)
            .args(["print", &format!("system/{LAUNCHD_LABEL}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        Ok(ScheduleStatus {
            installed: registered,
            detail: if registered {
                format!("{LAUNCHD_LABEL} is loaded")
            } else {
                format!("{LAUNCHD_LABEL} is not loaded")
            },
        })
    }

    fn require_root() -> Result<(), BrokerError> {
        // SAFETY: `geteuid` has no preconditions and is always safe to call.
        if unsafe { libc::geteuid() } == 0 {
            Ok(())
        } else {
            Err(BrokerError::Io(
                "registering the daily schedule requires root".into(),
            ))
        }
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
