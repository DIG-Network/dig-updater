//! Stopping + restarting an OS service around a binary replace (#666 Bug B).
//!
//! A service-backed component (dig-node, the OS service `net.dignetwork.dig-node`) holds its own
//! executable open while it runs, so a replace attempted against the running service either fails
//! with the file-in-use class (unix) or is DEFERRED by the OS installer's over-a-locked-file swap
//! (Windows MSI `/norestart`) — the update "succeeds" but the on-disk binary is not swapped
//! in-pass, and the post-install `--version` probe reads the still-old binary → the health gate
//! rolls it back. This module gives the applier the missing step: **stop the service, replace,
//! restart**, so the replace lands and the probe reads the NEW binary.
//!
//! Like every native tool this crate invokes ([`crate::install::trusted_absolute`]), the service
//! manager is resolved by its ABSOLUTE, trusted path — never a bare name resolved through `PATH`,
//! which a `PATH`/CWD-planted binary could hijack into root/SYSTEM code execution (#565/#657):
//!
//! | OS      | Stop                                   | Start                                       |
//! |---------|----------------------------------------|---------------------------------------------|
//! | Windows | `sc.exe stop <id>`                     | `sc.exe start <id>`                         |
//! | Linux   | `systemctl stop <unit>`                | `systemctl start <unit>`                    |
//! | macOS   | `launchctl bootout system/<id>`        | `launchctl bootstrap system <plist>`        |
//!
//! Windows `sc` and macOS `launchctl` address the FULL reverse-DNS id verbatim
//! (`net.dignetwork.dig-node`); the Linux systemd unit name is DERIVED from it
//! ([`linux_unit_name`]: drop the `net.` qualifier, hyphen-join the rest →
//! `dignetwork-dig-node`), matching the service-manager convention the installer registers under
//! (canonical skill, #502/#524).

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;

/// Which way to drive a service around a replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    /// Stop the service, releasing the lock on its executable so the replace can land.
    Stop,
    /// (Re)start the service after the replace — run in EVERY post-stop branch (success, deferral,
    /// or rollback) so a stopped service is never left down (#666 Bug B).
    Start,
}

/// The Linux systemd unit name for a reverse-DNS service id: drop the leading `net.` qualifier and
/// hyphen-join the remaining dotted segments (`net.dignetwork.dig-node` → `dignetwork-dig-node`),
/// matching the service-manager `ServiceLabel::to_script_name` the installer registers under
/// (canonical skill, #502/#524). An id without a `net.` prefix is dot→hyphen joined verbatim.
#[cfg(target_os = "linux")]
#[must_use]
pub fn linux_unit_name(service_id: &str) -> String {
    let rest = service_id.strip_prefix("net.").unwrap_or(service_id);
    rest.replace('.', "-")
}

/// Build the absolute-tool argv that performs `action` on `service_id`. Pure + cross-platform-
/// testable; the program at index 0 is always an ABSOLUTE, trusted path (or an error).
///
/// # Errors
///
/// A detail string if the platform's service manager cannot be resolved at a trusted absolute path,
/// or on an OS with no supported service manager.
pub fn service_argv(service_id: &str, action: ServiceAction) -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        let program = sc_program()?;
        let verb = match action {
            ServiceAction::Stop => "stop",
            ServiceAction::Start => "start",
        };
        Ok(vec![
            program.display().to_string(),
            verb.into(),
            service_id.to_string(),
        ])
    }
    #[cfg(target_os = "linux")]
    {
        let program = systemctl_program()?;
        let verb = match action {
            ServiceAction::Stop => "stop",
            ServiceAction::Start => "start",
        };
        Ok(vec![
            program.display().to_string(),
            verb.into(),
            linux_unit_name(service_id),
        ])
    }
    #[cfg(target_os = "macos")]
    {
        let program = launchctl_program()?;
        Ok(match action {
            ServiceAction::Stop => vec![
                program.display().to_string(),
                "bootout".into(),
                format!("system/{service_id}"),
            ],
            ServiceAction::Start => vec![
                program.display().to_string(),
                "bootstrap".into(),
                "system".into(),
                format!("/Library/LaunchDaemons/{service_id}.plist"),
            ],
        })
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (service_id, action);
        Err("no supported service manager on this OS".to_string())
    }
}

/// Drive `service_id` through `action` for real — the production [`ServiceControl`]. Resolves the
/// absolute service manager, runs it, and maps a non-success exit to a detail string.
///
/// # Errors
///
/// A detail string if the argv cannot be built (unresolvable tool) or the command fails / exits
/// non-zero.
pub fn control(service_id: &str, action: ServiceAction) -> Result<(), String> {
    let argv = service_argv(service_id, action)?;
    run(&argv)
}

/// A service-control function: stop or start a service by id. Injected into the applier so the
/// stop→replace→restart ORDERING + failure handling are unit-tested without touching a real service
/// manager (production wires [`control`]).
pub type ServiceControl<'a> = dyn Fn(&str, ServiceAction) -> Result<(), String> + 'a;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn run(argv: &[String]) -> Result<(), String> {
    use crate::proc::HideConsole;
    use std::process::Command;

    let Some((program, args)) = argv.split_first() else {
        return Err("empty service-control command".to_string());
    };
    match Command::new(program).args(args).hide_console().status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("{program} exited with {status}")),
        Err(e) => Err(format!("could not run {program}: {e}")),
    }
}

/// The absolute, trusted `sc.exe` (`%SystemRoot%\System32\sc.exe`) — never a bare name.
#[cfg(windows)]
fn sc_program() -> Result<PathBuf, String> {
    let system_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .ok_or_else(|| "neither %SystemRoot% nor %windir% is set".to_string())?;
    crate::install::trusted_absolute(PathBuf::from(system_root).join("System32").join("sc.exe"))
}

/// The absolute, trusted `systemctl` (`/usr/bin/systemctl`, falling back to `/bin/systemctl`).
#[cfg(target_os = "linux")]
fn systemctl_program() -> Result<PathBuf, String> {
    crate::install::first_trusted(&["/usr/bin/systemctl", "/bin/systemctl"])
}

/// The absolute, trusted `launchctl` (`/bin/launchctl`, falling back to `/usr/bin/launchctl`).
#[cfg(target_os = "macos")]
fn launchctl_program() -> Result<PathBuf, String> {
    crate::install::first_trusted(&["/bin/launchctl", "/usr/bin/launchctl"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unit_name_drops_the_net_qualifier_and_hyphen_joins() {
        // canonical: net.dignetwork.dig-node -> dignetwork-dig-node (#502/#524).
        assert_eq!(
            linux_unit_name("net.dignetwork.dig-node"),
            "dignetwork-dig-node"
        );
        assert_eq!(
            linux_unit_name("net.dignetwork.dig-dns"),
            "dignetwork-dig-dns"
        );
        // No `net.` prefix: dot->hyphen verbatim.
        assert_eq!(linux_unit_name("foo.bar"), "foo-bar");
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    #[test]
    fn service_argv_uses_an_absolute_trusted_program_for_both_actions() {
        for action in [ServiceAction::Stop, ServiceAction::Start] {
            match service_argv("net.dignetwork.dig-node", action) {
                Ok(argv) => {
                    assert!(
                        std::path::Path::new(&argv[0]).is_absolute(),
                        "the service manager is invoked by absolute path, never a bare name"
                    );
                }
                // On a runner missing the tool, resolution errors rather than falling back to PATH.
                Err(detail) => assert!(!detail.is_empty()),
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_addresses_the_full_reverse_dns_id_verbatim() {
        if let Ok(argv) = service_argv("net.dignetwork.dig-node", ServiceAction::Stop) {
            assert!(argv[0].to_lowercase().ends_with(r"system32\sc.exe"));
            assert_eq!(argv[1], "stop");
            assert_eq!(argv[2], "net.dignetwork.dig-node");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_addresses_the_derived_unit_name() {
        if let Ok(argv) = service_argv("net.dignetwork.dig-node", ServiceAction::Start) {
            assert!(argv[0].ends_with("systemctl"));
            assert_eq!(argv[1], "start");
            assert_eq!(argv[2], "dignetwork-dig-node");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_boots_the_daemon_out_to_stop_and_bootstraps_its_plist_to_start() {
        if let Ok(argv) = service_argv("net.dignetwork.dig-node", ServiceAction::Stop) {
            assert!(argv[0].ends_with("launchctl"));
            assert_eq!(argv[1], "bootout");
            assert_eq!(argv[2], "system/net.dignetwork.dig-node");
        }
        if let Ok(argv) = service_argv("net.dignetwork.dig-node", ServiceAction::Start) {
            assert_eq!(argv[1], "bootstrap");
            assert_eq!(argv[2], "system");
            assert_eq!(
                argv[3],
                "/Library/LaunchDaemons/net.dignetwork.dig-node.plist"
            );
        }
    }

    /// `control` runs the real service manager end-to-end (argv → run → status mapping). Driving it
    /// against a service id that provably does NOT exist maps the non-zero exit to an `Err` without
    /// touching any real DIG service and without needing elevation (a service manager reports an
    /// unknown service as absent to any caller). Skipped only if the tool cannot be resolved on this
    /// runner (a container without the service manager), where `service_argv` already errors.
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    #[test]
    fn control_maps_a_failed_service_command_to_an_error() {
        let bogus = "net.dignetwork.nonexistent-updater-666-test";
        if service_argv(bogus, ServiceAction::Stop).is_err() {
            return; // the platform service manager is not present on this runner
        }
        assert!(
            control(bogus, ServiceAction::Stop).is_err(),
            "stopping a nonexistent service maps the non-zero exit to an error"
        );
    }

    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    #[test]
    fn run_reports_an_empty_command_as_an_error() {
        assert!(super::run(&[]).is_err(), "an empty argv is a clean error");
    }
}
