#!/usr/bin/env bash
# Tests for the release helpers the release workflows call (scripts/*.sh).
#
# These are shell scripts that mutate a git working tree, so they are tested by running them
# against REAL throwaway git repositories rather than by mocking git. Every case here is a state
# the release workflows actually reach:
#
#   - the version pin is already correct        (dig-updater cutting release/0.19 while main is at
#                                                0.19.0 — the failure that motivated these tests)
#   - the version pin changes something         (the ordinary cut)
#   - Cargo.toml has no workspace version line  (must fail LOUDLY, never silently pin nothing)
#
# Run: bash scripts/tests/release-helpers.test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS="$REPO_ROOT/scripts"
PASS=0
FAIL=0

pass() {
  PASS=$((PASS + 1))
  echo "  ok   — $1"
}

fail() {
  FAIL=$((FAIL + 1))
  echo "  FAIL — $1"
  [ -n "${2:-}" ] && echo "         $2"
}

for script in set-workspace-version.sh commit-if-changed.sh; do
  if [ ! -f "$SCRIPTS/$script" ]; then
    echo "FATAL: scripts/$script does not exist — every case below would report a meaningless result"
    exit 1
  fi
done

# A throwaway repo with one commit, a workspace Cargo.toml at $1, and a lockfile.
new_repo() {
  local version="$1" dir
  dir="$(mktemp -d)"
  (
    cd "$dir" || exit 1
    git init -q .
    git config user.email "test@example.com"
    git config user.name "test"
    git config commit.gpgsign false
    # A REAL, resolvable single-crate workspace, so `cargo update --workspace` behaves exactly as it
    # does in the release job. A fixture with a dangling member would make cargo fail for a reason
    # that has nothing to do with the behaviour under test.
    printf '[workspace]\nmembers = ["crate-a"]\n\n[workspace.package]\nversion = "%s"\nedition = "2021"\n' \
      "$version" >Cargo.toml
    mkdir -p crate-a/src
    printf '[package]\nname = "crate-a"\nversion.workspace = true\nedition.workspace = true\n' \
      >crate-a/Cargo.toml
    : >crate-a/src/lib.rs
    cargo generate-lockfile -q 2>/dev/null || printf '# generated\nversion = 4\n' >Cargo.lock
    git add -A
    git commit -qm "initial"
  ) || return 1
  printf '%s' "$dir"
}

version_in() { grep -m1 -oE '^version = "[^"]+"' "$1/Cargo.toml" | cut -d'"' -f2; }
commit_count() { git -C "$1" rev-list --count HEAD; }

# ─────────────────────────── set-workspace-version.sh ───────────────────────────

echo "set-workspace-version.sh"

repo="$(new_repo 0.19.0)"
if (cd "$repo" && bash "$SCRIPTS/set-workspace-version.sh" 0.20.0 >/dev/null); then
  if [ "$(version_in "$repo")" = "0.20.0" ]; then
    pass "a differing version is pinned"
  else
    fail "a differing version is pinned" "got $(version_in "$repo")"
  fi
else
  fail "a differing version is pinned" "the script exited non-zero"
fi
rm -rf "$repo"

# THE MOTIVATING CASE. Pinning a version that is ALREADY correct is a legitimate no-op, not an
# error: it is exactly what happens when a repo opens its first release line at the version main
# already carries. An exit code here is what killed the real run.
repo="$(new_repo 0.19.0)"
if (cd "$repo" && bash "$SCRIPTS/set-workspace-version.sh" 0.19.0 >/dev/null); then
  if [ "$(version_in "$repo")" = "0.19.0" ]; then
    pass "an already-correct version succeeds and is left alone"
  else
    fail "an already-correct version succeeds and is left alone" "got $(version_in "$repo")"
  fi
else
  fail "an already-correct version succeeds" "the script exited non-zero on a no-op pin"
fi
rm -rf "$repo"

# Fail LOUDLY on a manifest it does not understand. A silent success here would push a release
# branch whose version was never actually set — the failure mode the exit code exists to prevent.
repo="$(mktemp -d)"
printf '[package]\nname = "x"\n' >"$repo/Cargo.toml"
if err="$( (cd "$repo" && bash "$SCRIPTS/set-workspace-version.sh" 0.20.0) 2>&1 )"; then
  fail "a Cargo.toml with no version line fails" "the script exited 0"
elif ! printf '%s' "$err" | grep -q 'version'; then
  fail "a Cargo.toml with no version line fails loudly" "the error said nothing useful: $err"
elif grep -q '0.20.0' "$repo/Cargo.toml"; then
  fail "a failed pin changes nothing" "the manifest was written anyway"
else
  pass "a Cargo.toml with no version line fails loudly, changing nothing"
fi
rm -rf "$repo"

# ─────────────────────────── commit-if-changed.sh ───────────────────────────

echo "commit-if-changed.sh"

repo="$(new_repo 0.19.0)"
(cd "$repo" && bash "$SCRIPTS/set-workspace-version.sh" 0.20.0 >/dev/null)
before="$(commit_count "$repo")"
if (cd "$repo" && bash "$SCRIPTS/commit-if-changed.sh" "chore(release): prep v0.20.0" Cargo.toml Cargo.lock >/dev/null); then
  if [ "$(commit_count "$repo")" -eq $((before + 1)) ] \
    && [ "$(git -C "$repo" log -1 --format=%s)" = "chore(release): prep v0.20.0" ]; then
    pass "a real change is committed with the given message"
  else
    fail "a real change is committed" "commits $before -> $(commit_count "$repo")"
  fi
else
  fail "a real change is committed" "the script exited non-zero"
fi
rm -rf "$repo"

# THE FAILURE THAT MOTIVATED THIS FILE. `git commit` with nothing staged exits 1 and killed the
# job before it pushed the branch or opened the next-dev PR. Already-in-the-desired-state is a
# SUCCESS, and it must not fabricate an empty commit either.
repo="$(new_repo 0.19.0)"
(cd "$repo" && bash "$SCRIPTS/set-workspace-version.sh" 0.19.0 >/dev/null)
before="$(commit_count "$repo")"
out="$(cd "$repo" && bash "$SCRIPTS/commit-if-changed.sh" "chore(release): prep v0.19.0" Cargo.toml Cargo.lock 2>&1)"
status=$?
if [ "$status" -ne 0 ]; then
  fail "an unchanged tree succeeds" "exit $status — this is the bug that broke the real release cut: $out"
elif [ "$(commit_count "$repo")" -ne "$before" ]; then
  fail "an unchanged tree creates no commit" "an empty commit was fabricated"
elif ! printf '%s' "$out" >/dev/null; then
  fail "an unchanged tree says so" "no output"
else
  case "$out" in
    *already*) pass "an unchanged tree succeeds, commits nothing, and SAYS it was already correct" ;;
    *) fail "an unchanged tree says so" "output did not report the already-correct state: $out" ;;
  esac
fi
rm -rf "$repo"

# Only the named paths are committed: a release-prep commit must never sweep up unrelated edits
# that happen to be in the tree (a stray build artifact, a partially-applied cherry-pick).
repo="$(new_repo 0.19.0)"
(cd "$repo" && bash "$SCRIPTS/set-workspace-version.sh" 0.20.0 >/dev/null)
printf 'unrelated\n' >"$repo/STRAY.txt"
(cd "$repo" && bash "$SCRIPTS/commit-if-changed.sh" "chore(release): prep v0.20.0" Cargo.toml Cargo.lock >/dev/null)
if [ "$(git -C "$repo" log -1 --format=%s)" != "chore(release): prep v0.20.0" ]; then
  fail "only the named paths are committed" "no release commit was made, so the check is vacuous"
elif git -C "$repo" show --stat --name-only HEAD | grep -q STRAY.txt; then
  fail "only the named paths are committed" "STRAY.txt was swept into the release commit"
else
  pass "only the named paths are committed"
fi
rm -rf "$repo"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
