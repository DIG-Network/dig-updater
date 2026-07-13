//! Regression guard for the v0.5.0 release-build failure (#504, run 29289135877).
//!
//! The release workflow builds both beacon binaries on a multi-OS matrix that includes a
//! Windows runner. GitHub Actions runs a `run:` step under the runner's DEFAULT shell, which
//! on Windows is PowerShell — and PowerShell does NOT understand the bash `\` line-continuation.
//! The v0.5.0 "Build both beacon binaries" step spelled the command across two lines with a
//! trailing `\`, so on `windows-latest` PowerShell parsed the second line's `--bin` as its `--`
//! unary operator and died with "Missing expression after unary operator '--'". No binaries were
//! staged, so no GitHub Release was published — the whole release pipeline went red.
//!
//! The fix is to make any release step that relies on bash line-continuation declare `shell: bash`
//! (GitHub-hosted Windows runners ship Git Bash), exactly as the neighbouring "Install Rust" and
//! "Stage both artifacts" steps already do. This test enforces that invariant so the class of bug
//! cannot silently return: every step in `release.yml` whose `run:` script uses a `\` continuation
//! MUST declare `shell: bash`.

use std::path::PathBuf;

/// `release.yml`, resolved relative to this crate so the test is location-independent.
fn release_workflow() -> String {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let path = repo_root
        .join(".github")
        .join("workflows")
        .join("release.yml");
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
    let workflow = release_workflow();
    let offenders: Vec<String> = steps_of(&workflow)
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
        "release.yml steps use a bash `\\` line-continuation without `shell: bash`, which \
         breaks on the Windows runner's default PowerShell (regression of #504): {offenders:?}"
    );
}

#[test]
fn build_both_binaries_step_runs_under_bash() {
    let workflow = release_workflow();
    let build_step = steps_of(&workflow)
        .into_iter()
        .find(|step| step.name == "Build both beacon binaries")
        .expect("release.yml must have a 'Build both beacon binaries' step");

    assert!(
        declares_bash_shell(&build_step),
        "the 'Build both beacon binaries' step must declare `shell: bash` so its multi-line \
         cargo invocation runs under bash on the Windows runner (regression of #504)"
    );
}
