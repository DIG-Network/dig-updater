//! Regression guard: a stable release must WAKE THE FEED, and must do so with a token that can
//! actually start a workflow run (dig_ecosystem#3046).
//!
//! Publishing a GitHub Release is not shipping. Users install from the signed feed at
//! `updates.dig.net`, and the feed used to refresh only on a 6-hourly cron — so a release stayed
//! invisible to every beacon for up to six hours while the release itself, and every check on it,
//! stayed green. `release.yml` now signals `feed.yml` with a `repository_dispatch` on publish.
//!
//! The guard that matters most here is the TOKEN. GitHub deliberately does not start a workflow run
//! from an event sent with the automatic `GITHUB_TOKEN` — its recursion guard. A dispatch sent with
//! it is accepted (HTTP 204) and starts NOTHING: the step goes green, the feed never runs, and the
//! release is invisible exactly as before. That is this ticket's own defect class — a release step
//! that reports success while silently doing nothing — reproduced inside the fix for it. Only a PAT
//! (`RELEASE_TOKEN`, which this repo already requires for tag pushes for the same reason) works.

use std::path::PathBuf;

/// The `repository_dispatch` event type `feed.yml` listens for. Both sides must spell it the same,
/// or the dispatch is accepted and silently matches no trigger.
const DISPATCH_EVENT_TYPE: &str = "component-released";

/// A workflow file from `.github/workflows/`, resolved relative to this crate.
fn workflow(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(".github")
        .join("workflows")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The step that sends the dispatch: the lines of the `Notify the feed…` step, from its `- name:`
/// marker to the next step marker at the same indentation.
fn notify_step() -> String {
    let release = workflow("release.yml");
    let mut out = Vec::new();
    let mut inside = false;
    for line in release.lines() {
        if line.starts_with("      - ") {
            if inside {
                break;
            }
            inside = line.contains("Notify the feed");
        }
        if inside {
            out.push(line);
        }
    }
    assert!(
        !out.is_empty(),
        "release.yml must have a step that notifies the feed a new version was released \
         (dig_ecosystem#3046): publishing the release does not make it installable"
    );
    out.join("\n")
}

/// The release must actually send the dispatch, spelled the way the feed listens for it.
#[test]
fn a_stable_release_dispatches_to_the_feed() {
    let step = notify_step();
    assert!(
        step.contains("/dispatches"),
        "the notify step must POST to the repository `dispatches` endpoint:\n{step}"
    );
    assert!(
        step.contains(&format!("event_type={DISPATCH_EVENT_TYPE}")),
        "the dispatch must use the {DISPATCH_EVENT_TYPE:?} event type feed.yml listens for — a \
         mismatched type is accepted by the API and silently matches no trigger:\n{step}"
    );
}

/// `feed.yml` must listen for exactly the type `release.yml` sends. These are two files that have to
/// agree on one string, and nothing fails loudly when they stop agreeing: the API accepts any
/// `event_type` and simply starts no run.
#[test]
fn the_sender_and_the_listener_agree_on_the_event_type() {
    assert!(
        workflow("feed.yml").contains(DISPATCH_EVENT_TYPE),
        "feed.yml must declare the {DISPATCH_EVENT_TYPE:?} repository_dispatch type that \
         release.yml sends, or every release dispatch is silently ignored"
    );
}

/// THE TRAP. A dispatch authenticated with the automatic `GITHUB_TOKEN` is accepted and starts no
/// workflow run, so the notify step would be green forever while the feed never woke.
#[test]
fn the_dispatch_uses_a_pat_because_github_token_silently_starts_nothing() {
    let step = notify_step();
    assert!(
        step.contains("secrets.RELEASE_TOKEN"),
        "the dispatch must authenticate with the `RELEASE_TOKEN` PAT:\n{step}"
    );
    for automatic in ["github.token", "secrets.GITHUB_TOKEN"] {
        assert!(
            !step.contains(automatic),
            "the dispatch uses `{automatic}`, the automatic token. GitHub does not start a \
             workflow run from an event sent with it, so this step would return 204, report \
             SUCCESS, and wake nothing — re-creating the silent-no-op defect (dig_ecosystem#3046) \
             inside its own fix. Use `secrets.RELEASE_TOKEN`.\n{step}"
        );
    }
}
