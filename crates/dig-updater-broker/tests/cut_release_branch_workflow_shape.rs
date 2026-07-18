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
//!   5. It sets the version + syncs the lock with `cargo update --workspace` (so `--locked` stays
//!      green) and pushes the prep commit to `release/X.Y`.
//!   6. It opens a NORMAL PR to bump main (main stays PR-only, never a direct push).

use std::path::PathBuf;

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
        wf.contains("cargo update --workspace"),
        "the cut job must sync Cargo.lock with `cargo update --workspace` after setting the version \
         (so `--locked` builds/tests stay green on the release branch)"
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

#[test]
fn opens_a_pr_to_bump_main_never_a_direct_push() {
    let wf = cut_release_branch();
    assert!(
        wf.contains("gh pr create"),
        "the next-dev-cycle main bump must go through a NORMAL PR (`gh pr create`) — main stays \
         PR-only, never a direct push"
    );
}
