//! Spawning child processes without a flashing console window (issue #577).
//!
//! On Windows a console-subsystem child — `schtasks`, `systemctl`, `launchctl`, `net`,
//! `icacls`, and other system tools spawned by the broker — is, by default, given a
//! brand-new console window when its parent has none. That window flashes on screen
//! and steals focus for the fraction of a second the child lives, which during the
//! beacon's schedule registration (several spawns) reads as a storm of blinking boxes.
//!
//! The Win32 `CREATE_NO_WINDOW` process-creation flag suppresses that console
//! entirely while leaving everything else about the child untouched: it still
//! runs, and its stdio is still captured by `.output()`/`.status()` exactly as before —
//! the flag governs console *allocation*, not stdio redirection.
//!
//! [`HideConsole::hide_console`] is the single, broker-wide way to apply it.
//! EVERY child spawn in this crate is threaded through it — one helper rather
//! than a `creation_flags` literal sprinkled across a dozen call sites — so no
//! spawn site can be missed, now or after a refactor. On non-Windows targets,
//! where there is no console to flash, it is a no-op, so the same call site
//! compiles and behaves identically on every platform.

/// The Win32 [`CREATE_NO_WINDOW`] process-creation flag: run a console child
/// without allocating a console, so no window flashes and the beacon keeps
/// foreground focus.
///
/// [`CREATE_NO_WINDOW`]: https://learn.microsoft.com/windows/win32/procthread/process-creation-flags
#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Suppress the transient console window Windows would otherwise allocate for a
/// child [`std::process::Command`].
///
/// The method is chainable, so it drops straight into an existing builder chain
/// immediately before `.output()`/`.status()`/`.spawn()`:
///
/// ```no_run
/// use dig_updater_broker::proc::HideConsole;
///
/// let out = std::process::Command::new("schtasks")
///     .arg("/Query")
///     .hide_console()
///     .output();
/// ```
///
/// On non-Windows targets this is a no-op (there is no console to hide), so the
/// same call site compiles and behaves identically everywhere.
pub trait HideConsole {
    /// Apply [`CREATE_NO_WINDOW`] on Windows (a no-op elsewhere), returning
    /// `self` so the call chains before the terminal spawn method.
    fn hide_console(&mut self) -> &mut Self;
}

impl HideConsole for std::process::Command {
    fn hide_console(&mut self) -> &mut Self {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A hidden child still RUNS and its stdout is still CAPTURED by `.output()`
    /// — the core #577 acceptance that `CREATE_NO_WINDOW` hides only the console
    /// and never disturbs stdio capture. Cross-platform: it also proves the
    /// non-Windows no-op is fully transparent.
    ///
    /// (`std::process::Command` exposes no getter for its creation flags, so the
    /// flag cannot be read back and asserted directly; this behavioural check —
    /// the child runs, exits zero, and its output is captured verbatim — is the
    /// observable contract the flag must preserve.)
    #[test]
    fn hidden_child_runs_and_its_output_is_still_captured() {
        let out = echoing_command("dig-577-token")
            .hide_console()
            .output()
            .expect("the hidden child should still spawn");
        assert!(out.status.success(), "the hidden child should exit zero");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("dig-577-token"),
            "the hidden child's stdout should still be captured"
        );
    }

    /// `hide_console` returns the same `Command` so it composes inside a builder
    /// chain (the property every call site relies on).
    #[test]
    fn is_chainable() {
        let mut cmd = echoing_command("chain");
        // Calling it twice is idempotent and still yields a usable command.
        let out = cmd
            .hide_console()
            .hide_console()
            .output()
            .expect("chained command should spawn");
        assert!(out.status.success());
    }

    /// On Windows the applied flag is exactly the documented Win32 value.
    #[cfg(windows)]
    #[test]
    fn create_no_window_is_the_win32_flag() {
        assert_eq!(CREATE_NO_WINDOW, 0x0800_0000);
    }

    /// Build a command that prints `token` to stdout and exits zero, using each
    /// OS's always-present shell so the test needs no fixture on disk.
    fn echoing_command(token: &str) -> Command {
        #[cfg(windows)]
        {
            let mut c = Command::new("cmd");
            c.args(["/C", "echo", token]);
            c
        }
        #[cfg(not(windows))]
        {
            let mut c = Command::new("printf");
            c.args(["%s", token]);
            c
        }
    }
}
