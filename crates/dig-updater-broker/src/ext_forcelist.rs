//! Keep the force-installed DIG extension on the beacon's tracked channel (#613).
//!
//! The universal installer force-installs the DIG Chrome extension into every detected Chromium
//! browser via each browser's `ExtensionInstallForcelist` managed policy (#602 Piece A, #612). One
//! extension id (`mlibddmbhlgogepnjdienclhnkfpkfah`) serves BOTH release channels; only the policy's
//! `update_url` differs per channel. When the operator switches the beacon's tracked channel
//! (`dig-updater channel set <nightly|stable>`, #591), the force-installed extension must FOLLOW —
//! the browsers must end up pulling from the newly-tracked channel's `update_url`.
//!
//! ## Why a channel switch is a REINSTALL, not a version bump (#607)
//!
//! The nightly version scheme `X.Y.Z.N` (`N` = UTC days since 2020-01-01) numerically OUTRANKS the
//! stable `X.Y.Z`, so a browser sitting on a nightly build is at a HIGHER version than any stable
//! build. Chromium will NOT auto-perform a downgrade. So simply rewriting the forcelist entry's
//! `update_url` in place — the single pass that `dig-installer --set-ext-forcelist-channel` writes
//! (#612) — leaves a nightly→stable switch stranded on the old, higher-versioned build.
//!
//! Crossing the downgrade requires a clean REINSTALL, STAGED across a policy-refresh cycle:
//!
//! 1. **REMOVE** the DIG forcelist entry from every browser (`--uninstall-ext-forcelist`). With the
//!    entry gone, each browser uninstalls the extension on its next managed-policy refresh.
//! 2. **AWAIT** that refresh: the browsers must OBSERVE the removal and actually uninstall the old
//!    build before the re-add — otherwise the re-add races the removal and the browser keeps the
//!    higher-versioned build, and the downgrade never crosses.
//! 3. **RE-ADD** the entry pointing at the target channel's `update_url`
//!    (`--set-ext-forcelist-channel <channel>`). With no extension present, this is a FRESH install
//!    of the target channel — not a blocked downgrade.
//!
//! This module owns only the STAGING orchestration (the ordering + the wait). The per-browser policy
//! write itself is single-sourced in `dig-installer` (#612); the beacon never re-implements it — it
//! shells the installer's two elevation-gated verbs. The beacon already runs privileged for updates,
//! so it can invoke them directly.

use std::path::PathBuf;
use std::time::Duration;

use crate::config::Channel;
use crate::paths;
use crate::proc::HideConsole;

/// How long to wait between removing the forcelist entry and re-adding it, so every browser observes
/// the removal and uninstalls the old (possibly higher-versioned) build before the re-add lands.
///
/// Chromium re-reads its managed policy periodically and applies `ExtensionInstallForcelist` changes
/// (installing new entries, uninstalling removed ones) on that refresh; there is no synchronous
/// "policy applied" signal to poll. On Windows the beacon nudges that refresh with `gpupdate`
/// ([`InstalledDigInstaller::refresh_policy`]) so the removal is picked up promptly; the wait then
/// gives the browser time to act on it. A deliberate operator-driven channel switch tolerates this
/// bounded pause.
pub const POLICY_REFRESH_WAIT: Duration = Duration::from_secs(15);

/// The two elevation-gated `dig-installer` forcelist verbs (#612), abstracted so the staging logic
/// in [`follow_channel_change`] is unit-testable without shelling out or touching real policy.
///
/// Production is [`InstalledDigInstaller`], which resolves the sibling `dig-installer` binary and
/// runs `--uninstall-ext-forcelist` / `--set-ext-forcelist-channel <channel>`.
pub trait ForcelistCommander {
    /// `dig-installer --uninstall-ext-forcelist`: remove ONLY the DIG extension's forcelist entry
    /// from every detected browser (idempotent; never touches a pre-existing org forcelist), so each
    /// browser uninstalls the extension on its next policy refresh.
    ///
    /// # Errors
    ///
    /// A human-readable detail if the installer could not be run or exited non-zero.
    fn remove(&self) -> Result<(), String>;

    /// `dig-installer --set-ext-forcelist-channel <channel>`: (re-)add the DIG forcelist entry across
    /// every detected browser pointing at `channel`'s `update_url`.
    ///
    /// # Errors
    ///
    /// A human-readable detail if the installer could not be run or exited non-zero.
    fn add(&self, channel: Channel) -> Result<(), String>;

    /// Nudge the OS to re-evaluate managed policy so the browsers observe the [`remove`](Self::remove)
    /// promptly (Windows `gpupdate`; a no-op where policy is file-based and picked up on the browser's
    /// own schedule). Best-effort — a failure to nudge is not fatal (the wait still covers the
    /// browser's own refresh cadence), so this returns nothing.
    fn refresh_policy(&self) {}
}

/// The outcome of a channel-follow attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtFollow {
    /// The tracked channel did not change — no policy writes were performed.
    Unchanged,
    /// The force-installed extension was reinstalled onto the target channel via the staged
    /// remove → refresh → re-add sequence.
    Reinstalled(Channel),
    /// The staged reinstall failed; the detail names the failing step. The forcelist may be in a
    /// transient state (entry removed but not yet re-added) — the deferred daily self-heal reconcile
    /// (#602 Piece B, not built here) re-asserts it.
    Failed(String),
}

/// Drive the force-installed extension to `to` when the tracked channel changes from `from`.
///
/// A no-op (no shelling, no policy writes) when `from == to`. Otherwise it stages the reinstall that
/// crosses the nightly↔stable version-ordering boundary (#607, see the module docs): REMOVE →
/// nudge + AWAIT the policy refresh → RE-ADD at `to`. The remove ALWAYS precedes the re-add, and the
/// wait ALWAYS sits between them, so a browser can never keep the old higher-versioned build.
///
/// `await_policy_refresh` is injected so tests drive the sequence with an instant, observable stub;
/// production passes [`InstalledDigInstaller::await_policy_refresh`].
pub fn follow_channel_change(
    from: Channel,
    to: Channel,
    commander: &impl ForcelistCommander,
    await_policy_refresh: impl FnOnce(),
) -> ExtFollow {
    if from == to {
        return ExtFollow::Unchanged;
    }

    // Phase 1 — REMOVE: strip the DIG forcelist entry so every browser uninstalls the old build.
    if let Err(e) = commander.remove() {
        return ExtFollow::Failed(format!("forcelist remove failed: {e}"));
    }

    // Phase 2 — AWAIT: nudge the OS to re-read policy, then wait for the browsers to observe the
    // removal and uninstall. Without this gap the re-add races the removal and the downgrade never
    // crosses (#607).
    commander.refresh_policy();
    await_policy_refresh();

    // Phase 3 — RE-ADD: reinstall pointing at the target channel's update_url. With no extension
    // present this is a fresh install, not a blocked downgrade.
    if let Err(e) = commander.add(to) {
        return ExtFollow::Failed(format!("forcelist re-add ({to}) failed: {e}"));
    }

    ExtFollow::Reinstalled(to)
}

/// The production [`ForcelistCommander`]: shells the sibling `dig-installer` binary's elevation-gated
/// forcelist verbs (#612). The beacon already runs privileged for updates, so the elevation the
/// installer requires is satisfied.
pub struct InstalledDigInstaller {
    installer: PathBuf,
}

impl InstalledDigInstaller {
    /// Resolve `dig-installer` as a sibling of the running beacon ([`paths::sibling_installer_binary`])
    /// — never a bare name found on `PATH`, which would be a privileged-code-execution foothold.
    ///
    /// # Errors
    ///
    /// [`crate::BrokerError`] if the current executable path cannot be determined.
    pub fn resolve() -> Result<Self, crate::BrokerError> {
        Ok(Self {
            installer: paths::sibling_installer_binary()?,
        })
    }

    /// The production `await_policy_refresh` callback: sleep [`POLICY_REFRESH_WAIT`] so the browsers
    /// have time to act on the forcelist removal before the re-add.
    pub fn await_policy_refresh() {
        std::thread::sleep(POLICY_REFRESH_WAIT);
    }

    /// Run the sibling installer with `args`, mapping "couldn't spawn" / non-zero exit to a detail.
    fn run(&self, args: &[&str]) -> Result<(), String> {
        if !self.installer.is_file() {
            return Err(format!(
                "dig-installer not found at {}",
                self.installer.display()
            ));
        }
        match std::process::Command::new(&self.installer)
            .args(args)
            .hide_console()
            .status()
        {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!(
                "{} {} exited with {status}",
                self.installer.display(),
                args.join(" ")
            )),
            Err(e) => Err(format!("could not run {}: {e}", self.installer.display())),
        }
    }
}

impl ForcelistCommander for InstalledDigInstaller {
    fn remove(&self) -> Result<(), String> {
        self.run(&["--uninstall-ext-forcelist"])
    }

    fn add(&self, channel: Channel) -> Result<(), String> {
        self.run(&["--set-ext-forcelist-channel", channel.as_str()])
    }

    fn refresh_policy(&self) {
        // Windows caches machine policy; `gpupdate /target:computer /force` makes the browsers pick
        // up the forcelist removal promptly instead of on their own slow cadence. Best-effort: any
        // failure just falls back to the browser's own refresh, which the wait already covers. On
        // Unix the managed-policy JSON/plist is re-read by each browser on its schedule, so there is
        // nothing to nudge.
        #[cfg(windows)]
        {
            if let Ok(gpupdate) = crate::install::trusted_absolute(std::path::PathBuf::from(
                r"C:\Windows\System32\gpupdate.exe",
            )) {
                let _ = std::process::Command::new(gpupdate)
                    .args(["/target:computer", "/force"])
                    .hide_console()
                    .status();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records the ordered sequence of forcelist verbs invoked, so a test can assert the remove
    /// precedes the re-add and the wait sits between them.
    #[derive(Default)]
    struct RecordingCommander {
        calls: RefCell<Vec<String>>,
        remove_fails: bool,
        add_fails: bool,
    }

    impl ForcelistCommander for RecordingCommander {
        fn remove(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("remove".to_string());
            if self.remove_fails {
                Err("boom".to_string())
            } else {
                Ok(())
            }
        }

        fn add(&self, channel: Channel) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("add:{channel}"));
            if self.add_fails {
                Err("boom".to_string())
            } else {
                Ok(())
            }
        }

        fn refresh_policy(&self) {
            self.calls.borrow_mut().push("refresh".to_string());
        }
    }

    #[test]
    fn an_unchanged_channel_performs_no_policy_writes() {
        let commander = RecordingCommander::default();
        let mut waited = false;
        let outcome = follow_channel_change(Channel::Stable, Channel::Stable, &commander, || {
            waited = true;
        });
        assert_eq!(outcome, ExtFollow::Unchanged);
        assert!(
            commander.calls.borrow().is_empty(),
            "a no-op channel-set must not touch any browser's forcelist"
        );
        assert!(!waited, "a no-op must not block on the policy-refresh wait");
    }

    #[test]
    fn a_channel_change_stages_remove_then_wait_then_readd_at_the_target() {
        let commander = RecordingCommander::default();
        let mut waited = false;
        let outcome = follow_channel_change(Channel::Nightly, Channel::Stable, &commander, || {
            waited = true
        });

        assert_eq!(outcome, ExtFollow::Reinstalled(Channel::Stable));
        assert!(
            waited,
            "the policy-refresh wait must run between remove and re-add"
        );
        // The ORDER is the contract that crosses the downgrade: remove (and its refresh nudge)
        // strictly before the re-add.
        assert_eq!(
            *commander.calls.borrow(),
            vec![
                "remove".to_string(),
                "refresh".to_string(),
                "add:stable".to_string()
            ]
        );
    }

    #[test]
    fn the_readd_targets_the_new_channels_update_url_for_both_directions() {
        // stable → nightly
        let commander = RecordingCommander::default();
        let outcome = follow_channel_change(Channel::Stable, Channel::Nightly, &commander, || {});
        assert_eq!(outcome, ExtFollow::Reinstalled(Channel::Nightly));
        assert_eq!(
            commander.calls.borrow().last().map(String::as_str),
            Some("add:nightly"),
            "switching to nightly must re-add pointing at the nightly channel"
        );
    }

    #[test]
    fn a_remove_failure_aborts_before_any_wait_or_readd() {
        let commander = RecordingCommander {
            remove_fails: true,
            ..Default::default()
        };
        let mut waited = false;
        let outcome = follow_channel_change(Channel::Nightly, Channel::Stable, &commander, || {
            waited = true
        });

        assert!(matches!(outcome, ExtFollow::Failed(_)));
        assert!(!waited, "a failed remove must not wait");
        assert_eq!(
            *commander.calls.borrow(),
            vec!["remove".to_string()],
            "a failed remove must never proceed to re-add (leaving the wrong build force-installed)"
        );
    }

    #[test]
    fn a_readd_failure_is_reported_after_the_remove_and_wait() {
        let commander = RecordingCommander {
            add_fails: true,
            ..Default::default()
        };
        let outcome = follow_channel_change(Channel::Stable, Channel::Nightly, &commander, || {});
        match outcome {
            ExtFollow::Failed(detail) => assert!(detail.contains("re-add")),
            other => panic!("expected a re-add failure, got {other:?}"),
        }
    }

    #[test]
    fn resolve_names_the_sibling_installer_binary() {
        let installer = InstalledDigInstaller::resolve().expect("resolves alongside the test exe");
        assert_eq!(
            installer.installer.file_name().and_then(|n| n.to_str()),
            Some(paths::installer_file_name())
        );
    }

    #[test]
    fn the_verbs_report_a_missing_installer_rather_than_shelling_a_bare_name() {
        // A commander pointed at a path with no file present must fail with a clear "not found"
        // detail — never fall through to a `PATH` lookup that could run a planted `dig-installer`.
        let commander = InstalledDigInstaller {
            installer: PathBuf::from("/nonexistent/dig-installer-nope"),
        };
        for result in [commander.remove(), commander.add(Channel::Stable)] {
            let detail = result.expect_err("a missing installer must be an error");
            assert!(
                detail.contains("not found"),
                "expected a not-found detail, got {detail:?}"
            );
        }
    }
}
