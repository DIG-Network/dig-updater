//! Regression guard for the feed workflow's publish control-flow (#545).
//!
//! `feed.yml` publishes the signed feed to TWO untrusted bases the beacon ships pointing at: the
//! PRIMARY S3 origin (updates.dig.net) and a FALLBACK rolling GitHub release. The bug U4 review
//! flagged: the fallback publish sat AFTER the HARD S3-primary publish + its byte-exact live smoke
//! and used the implicit `success()` gate, so a primary CloudFront hiccup that failed the smoke
//! (`exit 1`) SKIPPED the fallback — in exactly the outage the fallback exists to hedge. After the
//! 12-hour manifest expiry, beacons would then see an expired feed.
//!
//! The fix DECOUPLES the fallback from the primary edge WITHOUT weakening the trust keystone: the
//! fallback fires on `always() && steps.keystone.outcome == 'success'`, so a primary-edge failure
//! can no longer skip it, yet it still publishes ONLY when the pinned-key end-to-end verify passed.
//! These tests lock both halves of that invariant in place:
//!
//!   1. the fallback publish is NOT gated on the primary smoke's success, and
//!   2. it stays STRICTLY downstream of the verify keystone (never publishes an unverified feed).

use std::path::PathBuf;

/// The `feed.yml` step names this guard reasons about, spelled EXACTLY as they appear in the file.
const KEYSTONE_STEP: &str = "Verify the signed feed end-to-end (pinned key)";
const KEYSTONE_ID: &str = "keystone";
const S3_PUBLISH_STEP: &str = "Publish to updates.dig.net (S3 primary)";
const SMOKE_STEP: &str = "Smoke-test the live primary (byte-exact)";
const FALLBACK_STEP: &str = "Publish to the rolling `feed` release";

/// `feed.yml`, resolved relative to this crate so the test is location-independent.
fn feed_workflow() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
        .join("feed.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// A single `steps:` entry: its declared `- name:`, the value of its `if:` conditional (empty when
/// absent), and its ordinal position in the step list (0-based, for "runs before/after" reasoning).
struct Step {
    name: String,
    if_expr: String,
    order: usize,
}

/// Split a workflow into its step-list entries. A step begins at the 6-space `- ` indentation the
/// workflow uses for `steps:` items; deeper script/comment lines never match, so they stay grouped
/// under their owning step. A step's `if:` is read from the first `if:` line inside the step body.
fn steps_of(workflow: &str) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    for line in workflow.lines() {
        if line.starts_with("      - ") {
            let name = line
                .trim_start()
                .strip_prefix("- name:")
                .map(|n| n.trim().trim_matches('"').to_string())
                .unwrap_or_default();
            let order = steps.len();
            steps.push(Step {
                name,
                if_expr: String::new(),
                order,
            });
        }
        if let Some(step) = steps.last_mut() {
            if let Some(rest) = line.trim_start().strip_prefix("if:") {
                if step.if_expr.is_empty() {
                    step.if_expr = rest.trim().to_string();
                }
            }
        }
    }
    steps
}

/// Locate a step by its exact `name`, failing loudly if the workflow shape drifted out from under
/// this guard (a renamed step must consciously update the constants above).
fn step<'a>(steps: &'a [Step], name: &str) -> &'a Step {
    steps
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("feed.yml must have a step named {name:?}"))
}

/// A conditional "escapes" the implicit `success()` gate when it uses any status function that lets
/// a step run after an upstream failure/cancellation (`always()`, `!cancelled()`, `failure()`, …).
/// Such a step no longer inherits "all prior steps passed", so it MUST re-assert the trust keystone.
fn escapes_implicit_success(if_expr: &str) -> bool {
    ["always()", "cancelled()", "failure()"]
        .iter()
        .any(|marker| if_expr.contains(marker))
}

/// The fallback must publish only when the keystone verify SUCCEEDED — either by relying on the
/// implicit `success()` gate (positioned after the keystone) or, when it escapes that gate to
/// decouple from the primary edge, by explicitly re-asserting `steps.keystone.outcome == 'success'`.
fn gated_on_keystone_success(if_expr: &str) -> bool {
    if escapes_implicit_success(if_expr) {
        if_expr.contains(&format!("steps.{KEYSTONE_ID}.outcome == 'success'"))
            || if_expr.contains(&format!("steps.{KEYSTONE_ID}.conclusion == 'success'"))
    } else {
        true
    }
}

/// #545: the fallback publish must NOT be blocked by the primary smoke. It satisfies this either by
/// gating on `always()` (fires regardless of the smoke's outcome) or by running BEFORE the smoke.
/// Before the fix it did neither — implicit `success()`, positioned after the smoke — so this fails
/// on the old workflow and passes on the fixed one.
#[test]
fn fallback_publish_is_decoupled_from_primary_smoke() {
    let steps = steps_of(&feed_workflow());
    let fallback = step(&steps, FALLBACK_STEP);
    let smoke = step(&steps, SMOKE_STEP);

    let decoupled = fallback.if_expr.contains("always()") || fallback.order < smoke.order;
    assert!(
        decoupled,
        "the fallback GitHub-release publish is still gated on the primary smoke's success \
         (if: {:?}, ordered after the {SMOKE_STEP:?} step): a primary-edge hiccup that fails the \
         smoke would skip the very fallback it exists to hedge (#545). Gate it with `always()` or \
         move it before the smoke.",
        fallback.if_expr
    );
}

/// The trust keystone stays the single hard gate: the fallback publish must be positioned after the
/// end-to-end verify AND must never be able to run when that verify did not succeed. Decoupling from
/// the primary edge (#545) must not open a path to publishing an unverified feed.
#[test]
fn fallback_publish_stays_downstream_of_keystone_verify() {
    let steps = steps_of(&feed_workflow());
    let keystone = step(&steps, KEYSTONE_STEP);
    let fallback = step(&steps, FALLBACK_STEP);

    assert!(
        keystone.order < fallback.order,
        "the fallback publish must run AFTER the {KEYSTONE_STEP:?} keystone, never before it"
    );
    assert!(
        gated_on_keystone_success(&fallback.if_expr),
        "the fallback publish escapes the implicit success() gate (if: {:?}) without re-asserting \
         `steps.{KEYSTONE_ID}.outcome == 'success'`, so it could publish a feed the pinned-key \
         keystone did not verify (#545 must not regress the U4 trust posture)",
        fallback.if_expr
    );
}

/// Neither publish may precede the verify: the HARD S3 primary publish must also sit downstream of
/// the keystone. This complements the fallback guard so no publish path can serve an unverified feed.
#[test]
fn primary_publish_stays_downstream_of_keystone_verify() {
    let steps = steps_of(&feed_workflow());
    let keystone = step(&steps, KEYSTONE_STEP);
    let s3_publish = step(&steps, S3_PUBLISH_STEP);

    assert!(
        keystone.order < s3_publish.order,
        "the S3 primary publish must run AFTER the {KEYSTONE_STEP:?} keystone, never before it"
    );
}
