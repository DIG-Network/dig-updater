//! Shape guard for the professional nightlies release system (#590).
//!
//! This repo is the ecosystem's REFERENCE nightlies implementation, so its release
//! orchestrator (`nightly-release.yml`) has a precise, load-bearing shape that the fan-out
//! copies. These tests pin that shape so a careless edit — or a copy that drifts — cannot
//! silently revert the repo to the old "tag-and-release-on-every-merge" model:
//!
//!   1. The tagger NO LONGER triggers on push-to-main (the whole point of #590 — releases
//!      are batched to a nightly cron + manual dispatch instead of firing per merge).
//!   2. It DOES trigger on a midnight-UTC `schedule` cron and on `workflow_dispatch`.
//!   3. The STABLE channel keeps its idempotency keystone: skip cutting `vX.Y.Z` when that
//!      tag already exists (an unchanged version = the tag exists = a no-op).
//!   4. The NIGHTLY channel publishes a `prerelease: true` GitHub release under BOTH a dated
//!      `nightly-YYYYMMDD` tag and a force-moved rolling `nightly` tag, is never marked
//!      `latest`, and prunes old dated nightlies down to a retention window.
//!   5. Both channels preserve the RELEASE_TOKEN posture: no token configured => a clean
//!      no-op with a warning, never a half-release.
//!
//! The guard reads the workflow as text (not a YAML parser) on purpose: the invariants are
//! about the literal trigger/step shape a maintainer reads, and a text guard has no external
//! dependency and fails with a message that points at the exact line to fix.

use std::path::PathBuf;

/// A workflow file under `.github/workflows/`, resolved relative to this crate so the test is
/// location-independent (the crate sits two levels below the repo root).
fn workflow(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The nightly + manual-dispatch release ORCHESTRATOR — the converted on-merge tagger.
fn nightly_release() -> String {
    workflow("nightly-release.yml")
}

/// Extract a job's `if:` condition block: the lines from the job's `if:` key up to the next
/// sibling key at the same indentation (e.g. `runs-on:`). Returns the raw condition text so a
/// guard can assert on which trigger events can reach the job. `job` is the job key as it appears
/// at two-space indentation (e.g. `stable:`).
fn job_if_condition(workflow: &str, job: &str) -> String {
    let mut lines = workflow.lines().peekable();
    // Advance to the job declaration (`  <job>:` at two-space indent).
    let job_header = format!("  {job}");
    for line in lines.by_ref() {
        if line == job_header {
            break;
        }
    }
    // Within the job, capture the `if:` value block until the next key at four-space indent.
    let mut in_if = false;
    let mut captured: Vec<&str> = Vec::new();
    for line in lines {
        let is_job_key = line.starts_with("    ") && !line.starts_with("     ");
        if in_if && is_job_key && line.trim_start().contains(':') {
            break;
        }
        if line.trim_start().starts_with("if:") {
            in_if = true;
            captured.push(line);
            continue;
        }
        if in_if {
            captured.push(line);
        }
    }
    captured.join("\n")
}

/// Extract a workflow's top-level `on:` trigger block: the lines from `on:` (exclusive) up to
/// the next top-level key (a non-indented `word:` such as `jobs:`/`concurrency:`/`permissions:`).
/// Everything nested under `on:` stays; sibling top-level keys are excluded.
fn triggers_block(workflow: &str) -> String {
    let mut in_on = false;
    let mut lines: Vec<&str> = Vec::new();
    for line in workflow.lines() {
        if line.trim_start() == "on:" && !line.starts_with(' ') {
            in_on = true;
            continue;
        }
        if in_on {
            // A new top-level key (column-0, non-comment, non-blank) ends the `on:` block.
            let is_top_level_key = !line.is_empty()
                && !line.starts_with(' ')
                && !line.starts_with('#')
                && line.contains(':');
            if is_top_level_key {
                break;
            }
            lines.push(line);
        }
    }
    lines.join("\n")
}

#[test]
fn tagger_no_longer_triggers_on_push_to_main() {
    let on = triggers_block(&nightly_release());
    assert!(
        !on.contains("push:"),
        "nightly-release.yml still declares a `push:` trigger — #590 removed push-to-main so \
         releases are cut by the nightly cron + manual dispatch, NOT on every merge. `on:` block:\n{on}"
    );
}

#[test]
fn tagger_triggers_on_midnight_cron_and_manual_dispatch() {
    let on = triggers_block(&nightly_release());
    assert!(
        on.contains("schedule:"),
        "nightly-release.yml must trigger on a `schedule:` cron. `on:` block:\n{on}"
    );
    assert!(
        on.contains("0 0 * * *"),
        "the nightly cron must be `0 0 * * *` (midnight UTC — GitHub cron is UTC). `on:` block:\n{on}"
    );
    assert!(
        on.contains("workflow_dispatch:"),
        "nightly-release.yml must support `workflow_dispatch:` so a maintainer can cut a release \
         on demand (#590). `on:` block:\n{on}"
    );
}

#[test]
fn manual_dispatch_offers_channel_and_force_inputs() {
    let wf = nightly_release();
    let on = triggers_block(&wf);
    assert!(
        on.contains("channel:"),
        "workflow_dispatch must expose a `channel` input (stable | nightly | both). `on:` block:\n{on}"
    );
    assert!(
        on.contains("force:"),
        "workflow_dispatch must expose a `force` input (re-cut a stable release even if the \
         version is unchanged). `on:` block:\n{on}"
    );
}

#[test]
fn stable_job_keeps_the_skip_if_already_tagged_guard() {
    let wf = nightly_release();
    // The idempotency keystone: an unchanged version means `vX.Y.Z` already exists, so the run
    // must skip cutting it. Both the local + remote tag existence check and the skip signal must
    // survive the conversion, or the nightly cron would try to re-tag an already-released version.
    assert!(
        wf.contains("refs/tags/$TAG"),
        "the stable job must still check whether the version's `vX.Y.Z` tag already exists"
    );
    assert!(
        wf.contains("skip=true"),
        "the stable job must still short-circuit (skip=true) when the version's tag already exists"
    );
}

#[test]
fn force_recut_refuses_to_move_a_published_release_onto_a_different_commit() {
    let wf = nightly_release();
    // Supply-chain guard (#590 review): `force=true` may re-cut the SAME commit (a failed-build
    // retry) or repair a tag with no published release, but must NEVER silently move an existing
    // PUBLISHED release's tag onto a DIFFERENT commit — that would overwrite shipped binaries
    // with unreviewed code under the same version number. The force branch must (a) resolve the
    // existing tag's commit, (b) compare it against the commit this run would build, (c) check
    // whether a published (non-draft) GitHub release already sits at that tag, and (d) refuse
    // with a non-zero exit when both are true.
    assert!(
        wf.contains("TAG_COMMIT") && wf.contains("HEAD_COMMIT"),
        "the force branch must resolve both the existing tag's commit and this run's target \
         commit so it can compare them before moving the tag"
    );
    assert!(
        wf.contains("gh release view \"$TAG\"") && wf.contains("isDraft"),
        "the force branch must check whether a PUBLISHED (non-draft) release already exists at \
         the tag via `gh release view ... --json isDraft`"
    );
    assert!(
        wf.contains("IS_PUBLISHED_RELEASE") && wf.contains("TAG_COMMIT\" != \"$HEAD_COMMIT\""),
        "the force branch must refuse specifically when the release is published AND the tag's \
         commit differs from the target commit — same-commit re-cuts and no-release repairs \
         must remain allowed"
    );
    assert!(
        wf.contains("::error::refusing to force-move"),
        "the refusal must surface as a `::error::` annotation naming the guard, not a silent skip"
    );
}

#[test]
fn force_guard_fails_closed_on_a_transient_gh_lookup_error() {
    let wf = nightly_release();
    // #699: the "is there a PUBLISHED release at this tag?" lookup must FAIL CLOSED. A transient
    // GitHub API error (network / 5xx) must never be read as "no published release" and thus
    // permission to force-move a shipped tag. The old `gh release view ... || echo "false"` did
    // exactly that. The guard must (a) NOT default the published flag to false on ANY gh failure,
    // and (b) on an unknown/transient failure assume PUBLISHED so the move is refused.
    assert!(
        !wf.contains(r#"IS_PUBLISHED_RELEASE="$(gh release view "$TAG" --repo "$GITHUB_REPOSITORY" --json isDraft --jq '.isDraft == false' 2>/dev/null || echo "false")"#),
        "the force guard must not fall back to `|| echo \"false\"` — a transient gh error would be \
         read as 'no published release' and let the force-move through (fail-open)"
    );
    assert!(
        wf.contains("fail-closed") || wf.contains("fail closed"),
        "the force guard must document + implement a fail-CLOSED path for a gh lookup error"
    );
    assert!(
        wf.contains(r#"IS_PUBLISHED_RELEASE="true""#),
        "on an unknown/transient gh lookup failure the guard must set IS_PUBLISHED_RELEASE=true \
         (assume published → refuse the force-move)"
    );
}

#[test]
fn nightly_job_publishes_a_dated_and_a_rolling_prerelease() {
    let wf = nightly_release();
    assert!(
        wf.contains("--prerelease"),
        "the nightly job must publish a GitHub PRE-release (`--prerelease`), never a stable release"
    );
    assert!(
        wf.contains("nightly-$DATE") || wf.contains("nightly-${DATE}"),
        "the nightly job must publish under a DATED tag `nightly-YYYYMMDD` (built from $DATE)"
    );
    assert!(
        wf.contains("refs/tags/nightly"),
        "the nightly job must force-move a ROLLING `nightly` tag to the newest build"
    );
}

#[test]
fn nightly_release_is_never_marked_latest() {
    let wf = nightly_release();
    assert!(
        wf.contains("--latest=false"),
        "nightly releases must pass `--latest=false` — only a stable release may move `latest`, \
         so a nightly can never masquerade as the stable download (#590)"
    );
    assert!(
        !wf.contains("--latest=true"),
        "the nightly job must never mark a release `latest`"
    );
}

#[test]
fn nightly_job_prunes_to_a_retention_window() {
    let wf = nightly_release();
    // Retention keeps the newest N dated nightlies (default 14) + the rolling `nightly`, pruning
    // older dated releases AND their tags. The count is centralised in a `KEEP_NIGHTLIES` knob.
    assert!(
        wf.contains("KEEP_NIGHTLIES"),
        "the nightly job must define a `KEEP_NIGHTLIES` retention count"
    );
    assert!(
        wf.contains("--cleanup-tag"),
        "pruning must delete BOTH the GitHub release and its git tag (`gh release delete \
         --cleanup-tag`), never orphan a dated `nightly-YYYYMMDD` tag"
    );
}

#[test]
fn stable_is_cut_from_a_release_branch_nightly_stays_on_main() {
    // Epic #1049: the stable line moved OFF main. The STABLE job now cuts from a `release/X.Y`
    // branch (bound to `refs/heads/release/*`), while the NIGHTLY channel stays main-HEAD (the
    // nightly-meta job stays bound to `refs/heads/main`). A dispatch selected against the wrong ref
    // is an inert no-op for the wrong channel. This mirrors feed.yml's H1 ref-bind (#540/#616) —
    // the fleet-reaching push capability is bound to a curated ref, not any branch.
    let wf = nightly_release();
    let stable_if = job_if_condition(&wf, "stable:");
    assert!(
        stable_if.contains("startsWith(github.ref, 'refs/heads/release/')"),
        "the STABLE job `if:` must bind to `startsWith(github.ref, 'refs/heads/release/')` — \
         stable is cut from a release branch, never from main. stable `if:`:\n{stable_if}"
    );
    assert!(
        !stable_if.contains("github.ref == 'refs/heads/main'"),
        "the STABLE job must NOT be bound to main any more — it cuts from release/X.Y. \
         stable `if:`:\n{stable_if}"
    );
    let nightly_meta_if = job_if_condition(&wf, "nightly-meta:");
    assert!(
        nightly_meta_if.contains("github.ref == 'refs/heads/main'"),
        "the NIGHTLY channel must stay main-HEAD (nightly-meta bound to `refs/heads/main`) — \
         only the stable line moved to release branches. nightly-meta `if:`:\n{nightly_meta_if}"
    );
}

#[test]
fn stable_checks_out_and_pushes_the_dispatched_release_branch() {
    // The changelog commit + tag land on the CURATED release branch the dispatch selected, never on
    // main. Both the checkout ref and the changelog push target must be `github.ref_name` (the
    // dispatched `release/X.Y`), so main keeps moving independently.
    let wf = nightly_release();
    assert!(
        wf.contains("ref: ${{ github.ref_name }}"),
        "the stable job must check out the dispatched release branch (`ref: github.ref_name`), \
         not a hardcoded `ref: main`"
    );
    assert!(
        wf.contains("HEAD:${{ github.ref_name }}"),
        "the stable changelog commit must be pushed to the dispatched release branch \
         (`HEAD:github.ref_name`), not `HEAD:main`"
    );
    assert!(
        !wf.contains("git push origin \"HEAD:main\""),
        "the stable job must no longer push the changelog commit to main — it lands on release/X.Y"
    );
}

#[test]
fn schedule_cuts_only_nightlies_stable_is_manual_dispatch_only() {
    // Epic #1049 / CLAUDE.md §3.6: a stable `vX.Y.Z` tag is cut ONLY by a manual
    // `workflow_dispatch(channel: stable|both)` against a release branch. The midnight CRON runs on
    // main and cuts ONLY nightlies — it MUST NOT reach the stable changelog+tag job (the release/*
    // ref-bind already blocks it, but the workflow_dispatch gate is defense in depth). So the STABLE
    // job's `if:` must gate on `workflow_dispatch` and MUST NOT contain a `schedule` disjunct.
    let wf = nightly_release();
    let stable_if = job_if_condition(&wf, "stable:");
    assert!(
        !stable_if.contains("github.event_name == 'schedule'"),
        "the STABLE job `if:` must NOT be reachable from a `schedule` event — the cron cuts \
         nightlies only; stable is manual-dispatch-only (epic #1049). stable `if:`:\n{stable_if}"
    );
    assert!(
        stable_if.contains("github.event_name == 'workflow_dispatch'"),
        "the STABLE job `if:` must gate on `github.event_name == 'workflow_dispatch'` so only a \
         manual dispatch can cut a stable release. stable `if:`:\n{stable_if}"
    );
}

#[test]
fn both_channels_no_op_without_release_token() {
    let wf = nightly_release();
    assert!(
        wf.contains("RELEASE_TOKEN"),
        "the release orchestrator must gate on RELEASE_TOKEN"
    );
    assert!(
        wf.contains("::warning::"),
        "a missing RELEASE_TOKEN must degrade to a clear `::warning::` no-op, never a half-release"
    );
}
