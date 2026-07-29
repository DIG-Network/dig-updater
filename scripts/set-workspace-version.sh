#!/usr/bin/env bash
# Pin the workspace version in ./Cargo.toml to $1, and re-sync Cargo.lock to match.
#
# Called by the release workflows (cut-release-branch.yml) wherever a deliberate version has to be
# written onto a branch. Setting a version that is ALREADY the current one is a legitimate no-op and
# exits 0: opening a repo's first release line at the version main already carries is exactly that
# case, and treating it as an error is what broke dig-updater's first release cut.
#
# Not idempotent in one respect, deliberately: a Cargo.toml with no `[workspace.package]` version
# line is a hard FAILURE, not a silent skip. Exiting 0 there would push a release branch whose
# version was never actually set.
set -euo pipefail

VERSION="${1:?usage: set-workspace-version.sh <X.Y.Z>}"

python3 - "$VERSION" <<'PY'
import re
import sys

version = sys.argv[1]
text = open("Cargo.toml", encoding="utf-8").read()
# The single [workspace.package] version that members inherit via `version.workspace = true`. It is
# the FIRST bare `version = "…"` line in the manifest; dependency versions are all inside tables.
new, count = re.subn(r'(?m)^(version\s*=\s*")[^"]+(")', rf'\g<1>{version}\g<2>', text, count=1)
if count != 1:
    sys.exit("could not locate the [workspace.package] version line in Cargo.toml")
if new == text:
    print(f"Cargo.toml is already at {version} — nothing to pin.")
    sys.exit(0)
open("Cargo.toml", "w", encoding="utf-8").write(new)
print(f"Cargo.toml pinned to {version}.")
PY

# Re-sync the lockfile's own record of the workspace members' versions. `--workspace` limits the
# update to those members, so it never churns external dependencies and `--locked` builds stay green.
# Skipped when there is no lockfile to sync (a fresh repo, or a test fixture).
if [ -f Cargo.lock ] && command -v cargo >/dev/null 2>&1; then
  cargo update --workspace
fi
