//! Pure, OS-specific scheduler-artifact CONTENT builders — no I/O, no OS calls, so every builder
//! is unit-tested on every dev machine regardless of which OS it targets for real. Mirrors
//! dig-installer's `dns::plan` module: separate "what text do we write" from "how do we register
//! it with the OS" so the former is exercised everywhere and the latter only where it can run.

use std::path::Path;
use std::time::Duration;

/// Escape a string for use in XML element text or attribute values.
/// Replaces `&`, `<`, `>`, `"`, and `'` with their XML entity equivalents.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Quote a string for use in a systemd `ExecStart` value, handling spaces and special chars.
/// Wraps the string in double quotes and escapes internal backslashes and quotes.
fn escape_systemd_exec(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

/// The human-readable, discoverable identity the beacon's scheduled task/timer/daemon presents,
/// PARALLEL to the OS-service identities "DIG NETWORK: NODE" (dig-node) and "DIG NETWORK: DNS"
/// (dig-dns) — SYSTEM.md → "Canonical OS-service identity" (#494, #546). A user browsing Task
/// Scheduler / `systemctl` / `launchctl` sees the beacon under this name alongside the other DIG
/// services, and `dig-updater status` echoes it so the beacon's identity + health are legible.
///
/// This is a DISPLAY label only; the machine identifiers stay canonical and unchanged — the Windows
/// task path [`WINDOWS_TASK_PATH`], the systemd unit stem [`SYSTEMD_UNIT_NAME`], and the launchd
/// label [`LAUNCHD_LABEL`]. Changing this string is a cross-repo contract change (SYSTEM.md +
/// the `canonical` skill).
pub const BEACON_DISPLAY_NAME: &str = "DIG NETWORK: BEACON";

/// The Windows Task Scheduler path (folder + name) the daily pass registers under.
pub const WINDOWS_TASK_PATH: &str = r"\DIG\dig-updater";

/// The systemd unit stem (`<name>.service` + `<name>.timer` share it).
pub const SYSTEMD_UNIT_NAME: &str = "dig-updater";

/// The launchd label for the daily pass's LaunchDaemon.
pub const LAUNCHD_LABEL: &str = "net.dignetwork.dig-updater";

/// The local time-of-day every platform anchors its daily trigger to before jitter is applied.
pub const DAILY_AT: &str = "03:00:00";

/// How wide a window each OS spreads its jitter across, spreading fleet-wide load off a single
/// instant (SPEC §7 heartbeat + #504-F). Windows/systemd re-randomize this EVERY occurrence
/// natively; launchd has no such primitive, so [`launchd_jitter`] bakes one draw in at install time.
pub const JITTER_WINDOW: Duration = Duration::from_secs(2 * 60 * 60); // 2 hours

/// The Windows Task Scheduler XML definition that runs `<exe> run` once daily at [`DAILY_AT`],
/// jittered by up to `random_delay`, as SYSTEM at the highest available run level, with
/// `StartWhenAvailable` so a missed run (the machine was off or asleep) catches up as soon as it
/// is next available rather than waiting for tomorrow's occurrence (SPEC boot-recovery).
///
/// The `StartBoundary` date is a fixed anchor in the past — Task Scheduler only uses it to derive
/// the daily time-of-day for a recurring trigger; the trigger fires going forward from `now`
/// regardless of how far in the past the anchor date is.
///
/// The `exe` path is XML-escaped so paths with special characters (`&`, `<`, `>`, `"`, `'`)
/// do not break the XML structure.
pub fn windows_task_xml(exe: &Path, random_delay: Duration) -> String {
    let exe = escape_xml(&exe.display().to_string());
    let random_delay = duration_to_iso8601(random_delay);
    format!(
        // Declared UTF-16 to match how the CALLER (`scheduler::imp::install`, Windows) writes
        // this string to disk — `schtasks /XML` genuinely requires a UTF-16LE file with a BOM;
        // feeding it well-formed UTF-8 bytes fails with a cryptic "unable to switch the encoding"
        // at the declaration (confirmed live on a Windows CI runner). This `String` is ordinary
        // UTF-8 in Rust's own memory (as every Rust `String` is) — the encoding declared here is
        // a promise about the FILE bytes the caller produces, not about this in-memory value.
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>{WINDOWS_TASK_PATH}</URI>
    <Description>{BEACON_DISPLAY_NAME} — runs the DIG auto-update beacon once daily (SPEC #504-F).</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2020-01-01T{DAILY_AT}</StartBoundary>
      <Enabled>true</Enabled>
      <RandomDelay>{random_delay}</RandomDelay>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowHardTerminate>true</AllowHardTerminate>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>run</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// The systemd `dig-updater.service` unit: a `oneshot` run of `<exe> run`.
///
/// The `exe` path is quoted/escaped for systemd's `ExecStart` syntax to handle paths with
/// spaces or special characters correctly.
pub fn systemd_service_unit(exe: &Path) -> String {
    let exe = escape_systemd_exec(&exe.display().to_string());
    format!(
        "[Unit]\n\
         Description={BEACON_DISPLAY_NAME} — DIG auto-update beacon (one pass)\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={} run\n",
        exe,
    )
}

/// The systemd `dig-updater.timer` unit: daily, `RandomizedDelaySec` spread, and
/// `Persistent=true` so a missed run (the machine was off) catches up at the next boot (SPEC
/// boot-recovery) instead of waiting for tomorrow's occurrence.
pub fn systemd_timer_unit(random_delay: Duration) -> String {
    format!(
        "[Unit]\n\
         Description={BEACON_DISPLAY_NAME} — run the DIG auto-update beacon daily\n\
         \n\
         [Timer]\n\
         OnCalendar=daily\n\
         RandomizedDelaySec={}\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n",
        random_delay.as_secs(),
    )
}

/// The `net.dignetwork.dig-updater` LaunchDaemon plist: runs `<exe> run` daily at `(hour,
/// minute)` via `StartCalendarInterval`, plus `RunAtLoad` so a missed run (the machine was off)
/// catches up the next time launchd loads daemons at boot (SPEC boot-recovery). Runs as root (no
/// `UserName` key — a system LaunchDaemon defaults to root, matching dig-dns's plist convention).
///
/// The `exe` path is XML-escaped so paths with special characters (`&`, `<`, `>`, `"`, `'`)
/// do not break the plist XML structure.
pub fn launchd_plist(exe: &Path, hour: u32, minute: u32) -> String {
    let exe = escape_xml(&exe.display().to_string());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{LAUNCHD_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{exe}</string>\n\
         \t\t<string>run</string>\n\
         \t</array>\n\
         \t<key>StartCalendarInterval</key>\n\
         \t<dict>\n\
         \t\t<key>Hour</key>\n\
         \t\t<integer>{hour}</integer>\n\
         \t\t<key>Minute</key>\n\
         \t\t<integer>{minute}</integer>\n\
         \t</dict>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         </dict>\n\
         </plist>\n",
        exe = exe,
    )
}

/// Pick a per-machine jittered `(hour, minute)` around [`DAILY_AT`], spread across
/// [`JITTER_WINDOW`]. launchd has no native per-occurrence jitter (unlike Windows `RandomDelay` /
/// systemd `RandomizedDelaySec`, both re-drawn by the OS every run), so the spread is baked in
/// ONCE at install time from `entropy_nanos` — production draws that from the wall clock
/// (`SystemTime::now()` subsecond nanoseconds; load-spreading only, not security-sensitive), tests
/// inject a fixed value for determinism.
#[must_use]
pub fn launchd_jitter(entropy_nanos: u128) -> (u32, u32) {
    let window_minutes = (JITTER_WINDOW.as_secs() / 60) as u128;
    let offset_minutes = (entropy_nanos % window_minutes.max(1)) as u32;
    let base_minutes = 3 * 60; // DAILY_AT, 03:00, in minutes-past-midnight
    let total = (base_minutes + offset_minutes) % (24 * 60);
    (total / 60, total % 60)
}

/// Format a [`Duration`] as an ISO 8601 duration (`PT<seconds>S`) — the form Task Scheduler's
/// `RandomDelay`/`StartBoundary` XML elements require. Whole seconds are enough precision for a
/// multi-hour jitter window.
fn duration_to_iso8601(d: Duration) -> String {
    format!("PT{}S", d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn exe() -> PathBuf {
        PathBuf::from(r"C:\Program Files\DIG\dig-updater.exe")
    }

    #[test]
    fn every_scheduler_artifact_carries_the_discoverable_beacon_identity() {
        // #546: the beacon presents "DIG NETWORK: BEACON" wherever the OS surfaces it, PARALLEL to
        // dig-node's "DIG NETWORK: NODE" + dig-dns's "DIG NETWORK: DNS" (SYSTEM.md OS-service
        // identity contract). The machine identifiers stay canonical + unchanged.
        assert_eq!(BEACON_DISPLAY_NAME, "DIG NETWORK: BEACON");

        let win = windows_task_xml(&exe(), JITTER_WINDOW);
        assert!(
            win.contains(BEACON_DISPLAY_NAME),
            "the Windows task Description surfaces the beacon identity"
        );
        assert!(
            win.contains(&format!("<URI>{WINDOWS_TASK_PATH}</URI>")),
            "the task declares its canonical registration path"
        );

        let svc = systemd_service_unit(Path::new("/usr/local/bin/dig-updater"));
        assert!(
            svc.contains(&format!("Description={BEACON_DISPLAY_NAME}")),
            "the systemd service Description surfaces the beacon identity"
        );
        let timer = systemd_timer_unit(JITTER_WINDOW);
        assert!(
            timer.contains(&format!("Description={BEACON_DISPLAY_NAME}")),
            "the systemd timer Description surfaces the beacon identity"
        );

        // launchd's identity IS its canonical reverse-DNS label (macOS surfaces no separate friendly
        // name); the beacon's `status` line carries the display name on every OS.
        assert_eq!(LAUNCHD_LABEL, "net.dignetwork.dig-updater");
    }

    #[test]
    fn windows_task_xml_carries_the_jitter_boot_recovery_and_system_principal() {
        let xml = windows_task_xml(&exe(), JITTER_WINDOW);
        assert!(xml.contains("<RandomDelay>PT7200S</RandomDelay>"));
        assert!(xml.contains("<StartWhenAvailable>true</StartWhenAvailable>"));
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"), "runs as SYSTEM");
        assert!(xml.contains("<Command>C:\\Program Files\\DIG\\dig-updater.exe</Command>"));
        assert!(xml.contains("<Arguments>run</Arguments>"));
        assert!(xml.contains("<DaysInterval>1</DaysInterval>"), "daily");
    }

    #[test]
    fn systemd_service_unit_is_a_oneshot_run() {
        let unit = systemd_service_unit(Path::new("/usr/local/bin/dig-updater"));
        assert!(unit.contains("Type=oneshot"));
        // Path is quoted for proper shell-like semantics in ExecStart
        assert!(unit.contains("ExecStart=\"/usr/local/bin/dig-updater\" run"));
    }

    #[test]
    fn systemd_timer_unit_is_daily_with_jitter_and_boot_recovery() {
        let unit = systemd_timer_unit(JITTER_WINDOW);
        assert!(unit.contains("OnCalendar=daily"));
        assert!(unit.contains("RandomizedDelaySec=7200"));
        assert!(unit.contains("Persistent=true"), "boot-recovery catch-up");
        assert!(unit.contains("WantedBy=timers.target"));
    }

    #[test]
    fn launchd_plist_carries_the_calendar_interval_and_boot_recovery() {
        let plist = launchd_plist(Path::new("/usr/local/bin/dig-updater"), 4, 30);
        assert!(plist.contains(&format!("<string>{LAUNCHD_LABEL}</string>")));
        assert!(plist.contains("<integer>4</integer>"));
        assert!(plist.contains("<integer>30</integer>"));
        assert!(
            plist.contains("<key>RunAtLoad</key>\n\t<true/>"),
            "boot-recovery catch-up"
        );
        assert!(plist.contains("<string>/usr/local/bin/dig-updater</string>"));
        assert!(plist.contains("<string>run</string>"));
    }

    #[test]
    fn launchd_jitter_stays_within_the_configured_window_around_the_anchor() {
        let window_minutes = (JITTER_WINDOW.as_secs() / 60) as u32;
        for nanos in [0u128, 1, 59, 3_600_000_000_000, u128::MAX] {
            let (hour, minute) = launchd_jitter(nanos);
            assert!(hour < 24 && minute < 60);
            let total = hour * 60 + minute;
            let base = 3 * 60;
            // The draw lands within [base, base + window) modulo a day, matching `launchd_jitter`'s
            // own wraparound so the boundary case (`total` wrapping past midnight) still holds.
            let offset = (total + 24 * 60 - base) % (24 * 60);
            assert!(
                offset < window_minutes,
                "jitter {offset} must stay inside the {window_minutes}-minute window"
            );
        }
    }

    #[test]
    fn launchd_jitter_is_deterministic_for_the_same_entropy() {
        assert_eq!(launchd_jitter(12_345), launchd_jitter(12_345));
    }

    #[test]
    fn duration_to_iso8601_formats_whole_seconds() {
        assert_eq!(duration_to_iso8601(Duration::from_secs(90)), "PT90S");
        assert_eq!(duration_to_iso8601(Duration::ZERO), "PT0S");
    }

    #[test]
    fn escape_xml_handles_ampersand_and_angle_brackets() {
        assert_eq!(escape_xml("a&b"), "a&amp;b");
        assert_eq!(escape_xml("a<b"), "a&lt;b");
        assert_eq!(escape_xml("a>b"), "a&gt;b");
        assert_eq!(escape_xml("a\"b"), "a&quot;b");
        assert_eq!(escape_xml("a'b"), "a&apos;b");
    }

    #[test]
    fn escape_xml_leaves_safe_strings_unchanged() {
        assert_eq!(escape_xml("hello"), "hello");
        assert_eq!(
            escape_xml("/usr/local/bin/dig-updater"),
            "/usr/local/bin/dig-updater"
        );
    }

    #[test]
    fn escape_systemd_exec_quotes_paths_with_spaces() {
        assert_eq!(
            escape_systemd_exec("/path/with spaces/exe"),
            "\"/path/with spaces/exe\""
        );
    }

    #[test]
    fn escape_systemd_exec_escapes_quotes_and_backslashes() {
        assert_eq!(
            escape_systemd_exec("C:\\Program Files\\dig\\exe.exe"),
            "\"C:\\\\Program Files\\\\dig\\\\exe.exe\""
        );
        assert_eq!(escape_systemd_exec("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn windows_task_xml_escapes_exe_with_ampersand() {
        let exe_with_amp = Path::new("C:\\Program Files & More\\dig-updater.exe");
        let xml = windows_task_xml(exe_with_amp, Duration::from_secs(100));
        assert!(xml.contains("&amp;"), "XML should escape & in exe path");
        assert!(
            !xml.contains("Program Files & More"),
            "Raw & should not appear"
        );
    }

    #[test]
    fn systemd_service_unit_quotes_exe_with_spaces() {
        let exe_with_spaces = Path::new("/usr/local/bin/my updater/dig-updater");
        let unit = systemd_service_unit(exe_with_spaces);
        assert!(
            unit.contains("\"/usr/local/bin/my updater/dig-updater\" run"),
            "systemd should quote exe with spaces"
        );
    }

    #[test]
    fn launchd_plist_escapes_exe_with_ampersand() {
        let exe_with_amp = Path::new("/opt/a&b/dig-updater");
        let plist = launchd_plist(exe_with_amp, 3, 0);
        assert!(plist.contains("&amp;"), "plist should escape & in exe path");
        assert!(
            !plist.contains("a&b"),
            "Raw & should not appear in XML context"
        );
    }
}
