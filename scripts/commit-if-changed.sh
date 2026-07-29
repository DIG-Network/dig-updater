#!/usr/bin/env bash
# Commit the given paths with the given message — or report that they were already correct.
#
#   commit-if-changed.sh <message> <path>...
#
# Plain `git commit` exits 1 when nothing is staged, which turns "the tree is already in the desired
# state" into a job failure. For a release workflow that is the wrong answer twice over: the state it
# wanted is the state it has, and the steps AFTER the commit — pushing the branch, opening the
# next-dev PR — are the ones that actually matter. dig-updater's first release cut died exactly
# there, having created its release branch locally and pushed nothing.
#
# So: an already-correct tree is a SUCCESS, it says so on stdout, and it fabricates no empty commit.
# Only the named paths are staged, so a release commit can never sweep up an unrelated edit that
# happens to be sitting in the tree.
set -euo pipefail

MESSAGE="${1:?usage: commit-if-changed.sh <message> <path>...}"
shift
[ "$#" -gt 0 ] || {
  echo "usage: commit-if-changed.sh <message> <path>..." >&2
  exit 1
}

git add -- "$@"

# --cached compares the INDEX against HEAD, so this asks the only question that matters: would a
# commit of what is staged contain anything? (A `git diff --quiet` on the working tree would answer a
# different question and miss an already-staged change.)
if git diff --cached --quiet -- "$@"; then
  echo "already correct: $* match HEAD, so there is nothing to commit for \"$MESSAGE\"."
  exit 0
fi

git commit -m "$MESSAGE" -- "$@"
