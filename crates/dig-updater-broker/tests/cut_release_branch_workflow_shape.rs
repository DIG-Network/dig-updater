//! Shape guard for the release-branch cut workflow (#1051 / epic #1049).
//!
//! `cut-release-branch.yml` is the ONE deliberate act that opens a stable line: it branches
//! `release/X.Y` off main, sets the deliberate stable version in a prep commit, and opens a
//! "next dev cycle" PR bumping main. This repo is the ecosystem's REFERENCE for the release-branch
//! model, so the workflow's load-bearing shape is pinned here — a copy that drifts, or a careless
//! edit that drops a guard, fails this test with a pointer at the exact invariant to restore:
//!
//!   1. It is `workflow_dispatch`-only with `version` + `next_dev_version` inputs.
//!   2. It is bound to `refs/heads/main` (a line is cut off REVIEWED main only).
//!   3. It REFUSES when the `release/X.Y` branch or the `vX.Y.0` tag already exists (no re-open, no
//!      clobber of a shipped version).
//!   4. It no-ops cleanly without RELEASE_TOKEN (never a half-cut line).
//!   5. It sets the version + syncs the lock (so `--locked` stays green) and pushes the prep commit
//!      to `release/X.Y` — via the tested `scripts/` helpers, with NO bare `git commit` anywhere.
//!   6. It opens a NORMAL PR to bump main (main stays PR-only, never a direct push).
//!
//! These are assertions about SHAPE, deliberately: the helpers' BEHAVIOUR is tested against real git
//! repositories in `scripts/tests/release-helpers.test.sh`. What this file pins is that the workflow
//! still routes through them — a YAML that re-inlined the logic could reintroduce dig_ecosystem#1806
//! while every shell test stayed green.

use std::path::PathBuf;

/// A release helper script `scripts/<name>`, so an invariant can be pinned where it now LIVES rather
/// than where it used to be inlined.
fn helper(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn cut_release_branch() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
        .join("cut-release-branch.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn is_workflow_dispatch_only_with_version_inputs() {
    let wf = cut_release_branch();
    assert!(
        wf.contains("workflow_dispatch:"),
        "cut-release-branch.yml must be a manual `workflow_dispatch` — opening a stable line is a \
         deliberate human act"
    );
    assert!(
        !wf.contains("push:") && !wf.contains("schedule:"),
        "cut-release-branch.yml must NOT auto-trigger on push or schedule — it is dispatch-only"
    );
    assert!(
        wf.contains("version:") && wf.contains("next_dev_version:"),
        "the dispatch must expose `version` (X.Y.0) and `next_dev_version` (X.(Y+1).0) inputs"
    );
}

#[test]
fn is_bound_to_main() {
    let wf = cut_release_branch();
    assert!(
        wf.contains("github.ref == 'refs/heads/main'"),
        "the cut job must bind to `github.ref == 'refs/heads/main'` — a release line is cut off \
         reviewed main only (defense in depth, mirrors the release orchestrator)"
    );
}

#[test]
fn refuses_when_the_line_or_first_tag_already_exists() {
    let wf = cut_release_branch();
    assert!(
        wf.contains("refs/heads/$BRANCH") && wf.contains("refs/tags/$TAG"),
        "the cut job must check the remote for both the release branch and the first `vX.Y.0` tag \
         before opening the line"
    );
    assert!(
        wf.contains("already exists"),
        "the cut job must REFUSE (clear error) when the line or its first version already exists — \
         no re-open, no clobber of a shipped version"
    );
}

#[test]
fn no_ops_cleanly_without_release_token() {
    let wf = cut_release_branch();
    assert!(
        wf.contains("RELEASE_TOKEN") && wf.contains("::warning::"),
        "a missing RELEASE_TOKEN must degrade to a clear `::warning::` no-op, never a half-cut line"
    );
}

#[test]
fn sets_version_syncs_lock_and_pushes_the_prep_commit() {
    let wf = cut_release_branch();
    assert!(
        wf.contains("scripts/set-workspace-version.sh"),
        "the cut job must set the version through `scripts/set-workspace-version.sh` — the helper \
         tested against real git repositories, which treats an already-correct version as success \
         (dig_ecosystem#1806)"
    );
    assert!(
        helper("set-workspace-version.sh").contains("cargo update --workspace"),
        "the version helper must sync Cargo.lock with `cargo update --workspace` (so `--locked` \
         builds/tests stay green on the release branch)"
    );
    assert!(
        wf.contains("chore(release): prep v"),
        "the version bump must land as a `chore(release): prep vX.Y.0` commit on the release branch"
    );
    assert!(
        wf.contains(r#"git push origin "$BRANCH""#),
        "the cut job must push the new `release/X.Y` branch with its prep commit"
    );
}

/// THE dig_ecosystem#1806 REGRESSION GUARD, at the layer where the bug actually lived.
///
/// The first cut of dig-updater's release line died on `git commit` exiting 1 with nothing staged —
/// main already carried the version the line was opening at — and the job stopped before pushing the
/// branch or opening the PR, having done nothing at all. Every commit in this workflow must therefore
/// go through the guarded helper. The shell suite cannot catch a YAML that stops calling it, which is
/// exactly how this would come back.
#[test]
fn commits_only_through_the_guarded_helper_never_a_bare_git_commit() {
    let wf = cut_release_branch();
    // Comment lines are stripped first: the workflow's own header EXPLAINS the `git commit` failure
    // this guards against, and a guard that trips on the prose describing it would be unusable — the
    // next person would delete the explanation rather than the defect.
    let executable: String = wf
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !executable.contains("git commit"),
        "cut-release-branch.yml must not call `git commit` directly: a commit with nothing staged \
         exits 1 and kills the cut before the push and the next-dev PR (dig_ecosystem#1806). Use \
         `scripts/commit-if-changed.sh`, which treats an already-correct tree as success."
    );
    assert!(
        wf.matches("scripts/commit-if-changed.sh").count() >= 2,
        "BOTH mutating steps — the release-branch prep commit and the next-dev main bump — must go \
         through the guarded helper; each had its own bare `git commit`"
    );
    assert!(
        helper("commit-if-changed.sh").contains("git diff --cached --quiet"),
        "the helper must decide by comparing the INDEX against HEAD — the only question that answers \
         `would this commit contain anything?`"
    );
}

#[test]
fn opens_a_pr_to_bump_main_never_a_direct_push() {
    let wf = cut_release_branch();
    assert!(
        wf.contains("gh pr create"),
        "the next-dev-cycle main bump must go through a NORMAL PR (`gh pr create`) — main stays \
         PR-only, never a direct push"
    );
}
