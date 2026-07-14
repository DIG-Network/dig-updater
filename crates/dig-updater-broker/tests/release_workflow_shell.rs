//! Regression guard for the v0.5.0 release-build failure (#504, run 29289135877).
//!
//! A release step builds both beacon binaries on a multi-OS matrix that includes a Windows runner.
//! GitHub Actions runs a `run:` step under the runner's DEFAULT shell, which on Windows is
//! PowerShell — and PowerShell does NOT understand the bash `\` line-continuation. The v0.5.0
//! "Build both beacon binaries" step spelled the command across two lines with a trailing `\`, so
//! on `windows-latest` PowerShell parsed the second line's `--bin` as its `--` unary operator and
//! died with "Missing expression after unary operator '--'". No binaries were staged, so no GitHub
//! Release was published — the whole release pipeline went red.
//!
//! The fix: any step that relies on a `\` continuation AND can run on a Windows runner MUST declare
//! `shell: bash` (GitHub-hosted Windows runners ship Git Bash). #590 factored the cross-OS build
//! into the reusable `build-binaries.yml` (called by both `release.yml` and `nightly-release.yml`),
//! so the Windows-runner build steps now live THERE — the only workflow whose jobs target Windows
//! runners. The other workflows' `run:` steps execute on `ubuntu-latest`, where the default shell
//! is already bash, so a `\` continuation is safe and is intentionally out of this guard's scope.
//! This test scans `build-binaries.yml` and pins the invariant on the exact build step.

use std::path::PathBuf;

/// The reusable cross-OS build workflow — the only one with jobs on Windows runners, and the home
/// of the #504 build step. Resolved relative to this crate so the test is location-independent.
fn build_workflow() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
        .join("build-binaries.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// A single `steps:` entry — the lines from one `      - ` list marker up to the next one.
struct Step {
    name: String,
    lines: Vec<String>,
}

/// Split a workflow into its step-list entries. A step begins at the 6-space `- ` indentation the
/// workflow uses for `steps:` items; deeper `run:` script lines (`--bin …`) never match, so they
/// stay grouped under their owning step. A step's name is taken from a `- name:` marker line (steps
/// declared as `- uses:`/`- run:` are left unnamed).
fn steps_of(workflow: &str) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    for line in workflow.lines() {
        if line.starts_with("      - ") {
            let name = line
                .trim_start()
                .strip_prefix("- name:")
                .map(|n| n.trim().trim_matches('"').to_string())
                .unwrap_or_default();
            steps.push(Step {
                name,
                lines: Vec::new(),
            });
        }
        if let Some(step) = steps.last_mut() {
            step.lines.push(line.to_string());
        }
    }
    steps
}

/// A step relies on bash if any line of its `run:` script ends with a `\` continuation.
fn uses_bash_line_continuation(step: &Step) -> bool {
    step.lines.iter().any(|l| l.trim_end().ends_with('\\'))
}

/// A step runs under bash if it declares `shell: bash`.
fn declares_bash_shell(step: &Step) -> bool {
    step.lines.iter().any(|l| l.trim() == "shell: bash")
}

#[test]
fn every_backslash_continuation_step_declares_bash_shell() {
    let offenders: Vec<String> = steps_of(&build_workflow())
        .into_iter()
        .filter(|step| uses_bash_line_continuation(step) && !declares_bash_shell(step))
        .map(|step| {
            if step.name.is_empty() {
                "<unnamed step>".to_string()
            } else {
                step.name
            }
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "build-binaries.yml steps use a bash `\\` line-continuation without `shell: bash`, which \
         breaks on the Windows runner's default PowerShell (regression of #504): {offenders:?}"
    );
}

#[test]
fn build_both_binaries_step_runs_under_bash() {
    // The cross-OS build now lives in the reusable build workflow (#590).
    let build_step = steps_of(&build_workflow())
        .into_iter()
        .find(|step| step.name == "Build both beacon binaries")
        .expect("build-binaries.yml must have a 'Build both beacon binaries' step");

    assert!(
        declares_bash_shell(&build_step),
        "the 'Build both beacon binaries' step must declare `shell: bash` so its multi-line cargo \
         invocation runs under bash on the Windows runner (regression of #504)"
    );
}
