# DEVELOPMENT_LOG — dig-updater

Durable, high-signal realizations from building the beacon. Concise facts with context — not a
change diary.

## Trust core

- **Verify over the RECEIVED bytes, never a re-serialization.** The signature covers the exact
  payload bytes on the wire. Parsing a payload into a struct and re-serializing it drops any
  field the struct doesn't know, so an additive future feed would fail signature verification
  under an older beacon — silently breaking forward-compatibility (SPEC §5.2/§5.4). The fix:
  capture the raw payload slice with a `serde_json` `RawValue` envelope
  (`SignedManifest::from_json`) and verify over that. `signing_bytes()` is the SIGNER's
  canonicalization only. Regression test: `unknown_field_manifest_still_verifies`.
- **Key hygiene is structural.** The verify library takes the root `VerifyingKey` as a parameter;
  only the `dig-updater-worker` binary pins `BEACON_ROOT_PUBKEY_B64`. There is no env var / feature
  / request field that can substitute a key at runtime — so tests inject throwaway keys while the
  shipped binary's trust anchor is fixed at compile time. The spawn integration test proves the
  shipped binary rejects a test-signed feed.
- **Size cap is a disk-fill guard, not authenticity.** `min(4 × advisory_size, 2 GiB)`, enforced
  while streaming so a hostile CDN can't fill the disk before the digest rejects the bytes. Uses
  `saturating_mul` (an absurd advisory must not overflow). Distinct reject reason
  `artifact_too_large`.

## Windows gotchas (bit us during -D)

- **UAC installer-detection = error 740.** Windows auto-elevates any executable whose file name
  contains `update`/`updater`/`install`/`setup`/`patch`. Every beacon binary is `*updater*`, so
  without an embedded `asInvoker` manifest Windows refuses to launch them unelevated (os error
  740) — and the privileged broker could not spawn the unprivileged worker at all. Fixed in
  `.cargo/config.toml` via `link-arg=/MANIFEST:EMBED` + `/MANIFESTUAC:level='asInvoker'`, which
  covers the `cargo test` harness binaries too. (This is the Windows `asInvoker` manifest #504-F
  tracks, pulled forward out of necessity.)
- **`cargo-llvm-cov` and config rustflags.** llvm-cov's instrumentation coexists with
  `.cargo/config.toml` rustflags locally on Windows (coverage ran fine), but coverage is gated on
  the Linux runner where the manifest is irrelevant anyway.
- **Privilege-dropping needs OS primitives (the only `unsafe`).** Unix: `setgroups([])` +
  `setgid` + `setuid` in a `pre_exec` hook, fail-closed (verify uid 0 is unreachable afterward),
  and only when the broker is actually root. Windows: `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`
  + `CreateProcessAsUserW`. A restricted token is EXEMPT from `SeAssignPrimaryTokenPrivilege`, so
  spawn-as-user works when the broker runs as SYSTEM (production); when the host denies it (a
  non-admin dev/CI shell lacking `SeIncreaseQuotaPrivilege`) it falls back to a plain
  `CreateProcessW`. The same manual-pipe IPC is used by both branches, so the pipe path is
  exercised even on the fallback. Full low-integrity/AppContainer is #534.

## Persistence

- **State must fail closed, never reset.** A present-but-corrupt trust-state file is a hard error
  (`StateCorrupt`), NOT a silent reset to zeroed marks — a reset would re-enable a downgrade.
  Missing file = fresh install (initial). Writes are atomic (temp + rename). Unknown fields are
  preserved across a load→save round-trip so a fleet rollback to an older beacon never destroys
  state a newer one wrote.

## Install path — the privileged act (-E)

- **hashed == installed must be STRUCTURAL, not timed.** The staging dir is writable by the
  privilege-dropped worker, so hashing a staging file and then re-opening it BY PATH to install is a
  TOCTOU: a compromised worker swaps the bytes between the two opens. The fix is not a tighter
  window but no window: copy the staged bytes ONCE into a broker-private file the worker cannot
  write (a `dest` sibling for a raw binary → atomic rename; the hardened `<state>/apply` dir for a
  native package), hashing from the same read, then install from that private copy. A swap of
  staging afterward is inert. Proof test: `a_swap_of_staging_after_verify_does_not_change_the_installed_bytes`.
- **The worker's staged PATH is untrusted too, not just its bytes.** Canonicalize it and refuse
  anything that does not resolve strictly inside the staging dir (`StagedPathEscapesStaging`) before
  reading a byte — else `/tmp/evil` or a `..` escape redirects the install.
- **Native installers by ABSOLUTE path only.** `msiexec`/`installer`/`dpkg` spawned by bare name do
  a `PATH`/CWD search → root/SYSTEM code-exec if either is influenceable. Pin the absolute trusted
  location (`%SystemRoot%\System32\msiexec.exe`, `/usr/sbin/installer`, `/usr/bin/dpkg`) and reject
  if it is not there — never fall back to a name lookup.
- **Windows ACL self-check does NOT harden on its own.** The alpha-floor `classify_writability`
  reports every EXISTING path `AdminOnly` on Windows, so the repair-harden branch never fires there.
  A dir that is only "hardened" through `acl_self_check` is created but never `icacls`-locked on
  Windows. Harden the state / lkg / apply dirs EXPLICITLY up front (the lkg dir receives snapshots
  before any state advance, so it can't wait for the advance-time harden).
- **A manual rollback's floor comes from persisted state, not the caller.** The lkg record's digest
  is self-recorded beside the cached bytes, so a caller who also picks the floor could reinstate a
  below-floor (vulnerable) build. Read `rollback_floor_build` from the persisted, Admin/SYSTEM-only
  trust state instead. (`Broker::rollback` takes no floor arg.)

## Feed signing (-I)

- **One serializer, shared by signer + verifier.** `dig-updater-feedsign` signs via the trust
  core's own `SignedManifest::sign` / `SignedDelegation::sign` and emits with `.to_json()` (the raw
  signed payload embedded verbatim). It NEVER re-implements the wire format. That is what makes the
  signer/verifier agreement structural rather than hopeful — the hermetic `produced_feed_verifies_
  end_to_end` test and the CI keystone (pinned-key beacon verifies the signed feed) both prove it.
- **`BEACON_SIGNING_KEY` shape is uncertain, so normalize + assert.** The alpha key was made with
  `openssl genpkey -algorithm ed25519`, so the secret is most likely a PKCS#8 PEM. feedsign accepts
  three shapes — PKCS#8 PEM, base64 PKCS#8 DER, or base64 of the raw 32-byte seed — by stripping PEM
  armor, base64-decoding, and taking the 32-byte seed (raw, or the tail after the fixed 16-byte
  PKCS#8-v1 Ed25519 prefix `30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20`). Then it asserts the
  DERIVED public key equals the pinned `BEACON_ROOT_PUBKEY_B64` and refuses to sign otherwise — a
  key-hygiene mistake becomes a loud CI failure, never a silently-unverifiable feed.
- **`generated`/`sequence` is the wall clock, supplied IN.** The workflow passes `date +%s`; the
  signer never calls the clock (determinism + reproducibility). The unix timestamp doubles as the
  monotonic anti-freeze/anti-rollback high-water-mark, so the 6h cadence naturally advances it.
- **`build` packs `major·10⁶ + minor·10³ + patch`** (minor/patch < 1000, enforced) so a higher
  release always sorts higher for the anti-downgrade floor. Per component; the manifest-level
  `rollback_floor_build` is a single value compared to every component's build (alpha floor 0).

## Primary publish + transparency (#535 / #533)

- **The S3 key prefix MUST equal the beacon's `PRIMARY_FEED_BASE` path byte-for-byte.** The beacon
  fetches `https://updates.dig.net/v1/alpha/{delegation,manifest}.json`, so the feed publishes to
  `s3://<bucket>/v1/alpha/`. Objects go up with `Content-Type: application/json` and no
  content-encoding (§10.4 no-transform); CloudFront is CachingDisabled so no invalidation is needed
  and a fresh feed is served immediately. CI uses OIDC (`id-token: write` + `configure-aws-credentials`
  assuming `AWS_DEPLOY_ROLE_ARN`) — no static AWS keys. A live byte-exact smoke (curl the primary,
  `cmp` to the signed manifest) is the end-to-end proof the CDN serves it un-transformed.
- **Ed25519 (PureEdDSA) is not generally compatible with Rekor `hashedrekord`.** `hashedrekord`
  attests only a digest, but PureEdDSA verifies over the WHOLE message, so a server-side re-verify of
  the signature against a bare hash isn't possible — Rekor may reject the entry. The alpha step is
  therefore FAIL-SOFT + log-only (a Rekor outage/rejection NEVER blocks the 6h heartbeat), and the
  beacon-side inclusion-verify is deferred to beta (#533), which should switch to the full-artifact
  `rekord` type (the manifest is small + already public) or Ed25519ph. The transparency triple
  (signed bytes + detached raw 64-byte sig + targets SPKI-PEM) is DERIVED from the produced feed, so
  it can only ever reflect exactly what was published — no second serializer.
- **Ed25519 SPKI PEM is a fixed 12-byte prefix + the raw 32-byte key.** `30 2a 30 05 06 03 2b 65 70
  03 21 00` then the key (44 bytes DER), base64-wrapped at 64 cols between `PUBLIC KEY` armor — the
  form `rekor-cli --pki-format=x509 --public-key` accepts. (Mirrors the 16-byte PKCS#8-v1 PRIVATE
  prefix used on the signing side.)
- **Asset match is exact.** `{prefix}-{version}-{token}` where token ∈ {`linux-x64`,`macos-arm64`,
  `macos-x64`,`windows-x64.exe`}. Exactness is load-bearing: a digstore release also ships `digs-…`
  and `digstore-…-x86_64-unknown-linux-gnu.tar.gz`; only the exact binary name is an artifact.
- **The `feed` release MUST be `--prerelease --latest=false`.** Otherwise it shadows the dig-updater
  component's own `/releases/latest`, since the feed resolves dig-updater from the SAME repo it
  publishes the feed to.
- **Publish is gated on the end-to-end verify.** feed.yml orders sign → serve locally →
  pinned-key `dig-updater check --feed-base …` (must report `status:verified`) → publish. A feed
  that does not verify is never served; the previous feed simply expires (12h) if a run is skipped.
- **Byte-identical serving is a hard requirement.** The verifier checks the signature over the
  RECEIVED bytes, so any transport transform of the JSON breaks it. Origins must serve verbatim.

## Scheduler, lock, self-update (-F)

- **A Windows named-mutex DACL breaks `CreateMutexW`'s OWN "open existing" path, not just other
  processes.** `CreateMutexW` on an object that already exists performs an implicit OPEN with a
  fixed desired access; if the caller's token cannot satisfy the object's DACL, the call fails
  outright with `ERROR_ACCESS_DENIED` — it does NOT fall back to a lesser access. This means an
  Administrators/SYSTEM-only DACL (correct for production) makes even a SECOND call from the SAME
  unprivileged process unable to detect contention — `cargo test`'s default (non-elevated) token
  cannot probe it. Fix: split the mutex creation path — the fixed production name always uses the
  restrictive DACL; a separate test-only entry point (`try_acquire_named`) uses the OS default
  security so contention is exercisable from an ordinary `cargo test` run, and the production DACL
  itself is only re-verified in the `scheduler-elevated` job in `ci.yml`.
- **Rust's `std::fs::File` opens with `FILE_SHARE_DELETE` on Windows by default.** Contrary to the
  classic "can't delete an open file on Windows" folklore, Rust's std opens with all three share
  flags (read/write/delete) unless you override `share_mode` via `OpenOptionsExt`. A test meaning
  to simulate "the destination is locked against rename" must explicitly `.share_mode(FILE_SHARE_READ)`
  (denying write+delete while still allowing a concurrent digest read) — a plain `File::open` will
  NOT block a rename and silently defeats the test's premise.
  (`a_deferred_self_update_never_gates_the_other_components_state_advance`.)
- **A component's OWN pre-existing-directory or broken-parent-directory trick fails at
  snapshot/staging time, not install time.** Forcing an install-step failure by making `dest` a
  directory, or its parent a non-directory file, actually errors EARLIER — `LkgCache::snapshot`'s
  `sha256_file` on a directory, or `stage_and_verify_private`'s `create_dir_all` on a blocked
  parent — which `?`-propagates as a hard `BrokerError` and aborts the WHOLE pass instead of
  producing a graceful per-component `Deferred`/`Failed` outcome. To test ONLY the install step,
  the induced failure must leave `dest` absent (a clean fresh-install snapshot) and its parent a
  real, writable directory (the file-locking trick above is the portable way to do this on
  Windows; there is no Unix equivalent, since Unix permits renaming over a busy file by design —
  see the next point).
- **On Windows, renaming DIRECTLY onto a currently-executing image is unreliable; the fix is the
  well-known two-rename dance, not a single `MoveFileEx`.** Rename-over-self "usually" works on
  Windows because the loader shares delete/rename access on the running image, but relying on a
  single rename for the SELF case specifically (vs. every other raw-binary component, where a
  locked target just retries/defers) risks a sharing violation right when it matters most. The
  robust pattern every long-lived Windows self-updater uses: rename the running image aside to a
  `.old` sibling FIRST, then rename the verified copy into the vacated name; undo the first rename
  if the second fails, so the beacon is never left without a working binary.
- **The XML `encoding=` declaration must match the bytes actually on disk.** `std::fs::write` of a
  Rust `String` always writes UTF-8; declaring `encoding="UTF-16"` in the Task Scheduler XML
  prolog while the file is actually UTF-8 bytes is a real mismatch (caught before shipping, not
  found live) — Task Scheduler's parser decodes per the declared encoding, so encoding and bytes
  must agree; declare `UTF-8` to match what is actually written.
- **The self-update's outcome must NOT gate whether the trust state advances for every other
  component.** The four monotonic marks (§6) track manifest FRESHNESS, not which binary the
  beacon itself currently is — a merely `Deferred` self-swap (locked target, common and benign) is
  therefore reported independently and never blocks the rest of a fully-successful pass from
  being recorded as such.
- **Real OS-registration tests that target ONE machine-global artifact race under `cargo test`'s
  default parallelism.** Unlike the lock's mutex (which has an injectable NAME per test), the
  scheduler artifact has exactly one canonical identity (one Task path / one systemd unit pair /
  one launchd label) — every test in `tests/scheduler.rs` mutates the SAME one. Running them
  concurrently let one test's `uninstall` land between another's `install` and its `status` check,
  failing an assertion that had nothing wrong with the code under test (caught live in the
  elevated CI job on the ubuntu runner). Fix: a single `static Mutex<()>` in the test file, held
  for each test's full body — the same shape as `dig-relay`'s `ENV_LOCK` for its env-mutating
  tests, applied here to OS-mutating ones instead.

## CLI: config + status (-G)

- **A "grant read to Everyone" Windows DACL must ALSO keep the OWNER RIGHTS ACE, or the owner locks
  itself out of what it just created.** `harden_state_dir`'s Admin+SYSTEM DACL already carries the
  `S-1-3-4` (owner rights) ACE specifically so a non-Administrator owner (a dev/CI process, or the
  installer before the beacon ever runs as SYSTEM) keeps write access to what it created. The new
  world-readable `harden_public_status_path` initially omitted that same ACE (Administrators +
  SYSTEM + Everyone-read only) — which meant the FIRST `icacls` call (run by the owning, unelevated
  process) succeeded, but the very next `std::fs::write` into that now-locked-down directory failed
  with `Access is denied. (os error 5)`, because the owner itself was no longer in the grant. Same
  root cause as the original `harden_windows_path` design note, re-learned the hard way on a new
  call site — a reminder to copy the FULL rationale, not just the shape, when writing a sibling
  hardening function.
- **A hardcoded "future" unix timestamp in a test is a time bomb.** A test asserting "this pause
  deadline hasn't passed yet" using a literal like `1_700_000_000` (Nov 2023) silently starts
  failing once the real wall clock passes that instant — it already had, on this dev machine's
  clock. Use `u64::MAX` (or `now_unix_secs() + offset`) for "far enough in the future to never
  lapse during this test" instead of a calendar-literal that will eventually become the past.
- **`config.json` deliberately does NOT preserve unknown fields like `trust-state.json` does.**
  `TrustStateStore` round-trips a raw `serde_json::Map` specifically so a fleet rollback to an
  older beacon never destroys a newer field that feeds an anti-downgrade decision (SPEC §9.5). The
  channel/pause config carries no such invariant — a plain typed struct with `#[serde(default)]`
  per field is simpler and equally correct, and is the intentional asymmetry: not every on-disk
  store in this crate needs the SAME persistence idiom, only the ones whose fields are
  security-load-bearing.
- **`status.json` must be a SIBLING directory of `state_dir`, never nested inside it.**
  `harden_state_dir`'s Windows DACL uses `(OI)(CI)` (object-inherit/container-inherit), so anything
  created INSIDE `state_dir` after it is hardened inherits the Admin/SYSTEM-only grant — a
  `status.json` living at `<state_dir>/status.json` would silently stop being world-readable the
  next time `state_dir` gets re-hardened. Deriving the status directory as `state_dir`'s OWN
  parent + `-status` suffix (`paths::sibling_status_dir`) keeps it structurally outside that
  inheritance and keeps a test's arbitrary tempdir-based `state_dir` and the real default
  automatically in lockstep, with no second hard-coded path to drift.

## Dry check must run unelevated (-I keystone, #540)

- **A dry `check` STAGES to disk, so an unwritable state dir turns a VALID feed into a
  `staging_io_error` rejection — not a status-write problem.** The signed-feed keystone (`feed.yml`)
  runs `dig-updater check` UNELEVATED on the CI runner. The worker downloads + digest-verifies each
  artifact by streaming it into `create_dir_all(<state_dir>/staging)`; under the Admin-only default
  (`/var/lib/dig-updater`) that create is denied (EACCES), and because staging is load-bearing for
  the digest check, a correctly-signed feed that verified cleanly comes back as a `Rejected`
  (`staging_io_error`) → `check` exits 2 → the keystone's `.status=="verified"` never emits. The
  `could not refresh status.json` line in the same log is a CO-SYMPTOM of the same unwritable dir,
  and that path was ALREADY fail-soft (a warning, never the exit code). Fix: `Broker::for_dry_check`
  resolves its state dir from `$DIG_UPDATER_STATE_DIR` (dry-check ONLY — the install/full-pass path
  stays pinned to the hardened default so anti-rollback is never relocatable), and `feed.yml` points
  the keystone step at a writable `${{ runner.temp }}` dir. Regression evidence:
  `valid_feed_with_an_uncreatable_staging_dir_reports_staging_io_not_a_verification_failure`
  (worker e2e — the exact conflation) + `for_dry_check_honors_the_state_dir_env_override`.
- **A test feed can never exercise the staging step through the broker/CLI.** The shipped worker
  pins the production key, so any locally-signed feed is rejected at `verify_update_chain` (step 5)
  BEFORE `create_dir_all(staging)` (step 6). The staging path is therefore only reachable in a
  worker-level test that injects a matching test root key (`worker::run(req, test_root)`) — which is
  why the #540 reproduction lives in `dig-updater-worker/tests/e2e.rs`, not the broker's.

## Release CI

- **A GitHub Actions `run:` step defaults to PowerShell on the Windows runner — a bash `\`
  line-continuation silently breaks there.** The v0.5.0 release went red because `release.yml`'s
  "Build both beacon binaries" step wrapped its cargo invocation across two lines with a trailing
  `\` but did not set `shell: bash`. On `windows-latest` PowerShell ran it, read the second line's
  `--bin` as its own `--` unary operator, and died with "Missing expression after unary operator
  '--'" — so no binaries staged and no GitHub Release published (run 29289135877, #504). The PR's
  `ci.yml` build never caught it because that job builds with a SINGLE-LINE command, which
  PowerShell handles. Rule: any `run:` step that relies on bash syntax (`\` continuation, `$VAR`,
  `[ ]` tests) on a multi-OS matrix MUST declare `shell: bash` (Git Bash ships on every hosted
  runner). Regression guard: `tests/release_workflow_shell.rs` asserts every `\`-continuation step
  in the cross-OS build workflow declares `shell: bash`.

- **Nightlies system (#590): the cron detecting "the version's tag doesn't exist yet" IS the
  version-changed check — no diffing needed.** Converting the on-merge tagger to a nightly cron kept
  ALL the stable logic verbatim; only the trigger changed (`push: branches: main` →
  `schedule: '0 0 * * *'` + `workflow_dispatch`). Because the stable job already skipped when the
  `vX.Y.Z` tag existed, running it nightly instead of per-merge needs zero new "did the version
  change?" logic: an unchanged version = the tag exists = a no-op; a bumped version = a new tag =
  cut. The old `!startsWith(head_commit.message, 'chore(release):')` loop-guard becomes INERT on
  schedule/dispatch (there is no `head_commit`), but is harmless and kept as defense if a push
  trigger is ever re-introduced.
- **Nightly version is synthesized at BUILD time, never committed:**
  `X.Y.Z-nightly.YYYYMMDD.<shortsha>` (semver prerelease → sorts below `X.Y.Z`, so a nightly can
  never outrank the stable release of the same version). Dated tag `nightly-YYYYMMDD` for history +
  a force-moved rolling `nightly` tag for a stable "latest nightly" URL. Always `--prerelease
  --latest=false` — only a stable release moves `latest`.
- **Rolling-release asset hygiene:** because nightly filenames carry the date+sha, `gh release
  upload --clobber` alone would let yesterday's assets linger on the rolling `nightly` release
  forever (different names never collide). The publish step deletes ALL existing assets
  (`gh release delete-asset`) before uploading this run's — for both the dated and the rolling tag.
- **`nightly*` tags must NOT match the stable build's `v*` trigger.** `release.yml` is
  `on: push: tags: v*`; `nightly-YYYYMMDD` and `nightly` don't match, so the nightly channel builds
  + publishes directly and never accidentally fires the stable-release build.
- **Reusable build (`build-binaries.yml`, `on: workflow_call`) is the DRY win of the reference:**
  both `release.yml` (stable) and the nightly channel call it, so the two paths can't diverge on how
  a binary is produced. Artifacts uploaded inside a called reusable workflow ARE downloadable by the
  caller's later jobs (same run id). The #504 Windows-shell guard follows the build step to
  wherever it lives — now `build-binaries.yml`, the ONLY workflow with Windows-runner jobs (the
  scan is scoped to it; ubuntu-only steps in other workflows already default to bash and are
  intentionally out of scope, else the guard false-positives).
- **Fan-out caveats flagged for the templates:** npm stacks replace the OS matrix with an npm
  publish under a `nightly` dist-tag (never `latest`); static-site services have no binary artifact
  (a nightly = an optional deploy to a nightly origin); Rust crates publish to crates.io on the
  stable tag (a crates.io "nightly" isn't meaningful — nightly is GitHub-prerelease-only there).
  The stable-channel cron conversion + the RELEASE_TOKEN/idempotency posture are the portable core.

## "Beacon never updates" — the three LIVE P1 root causes (#546/#580/#581, v0.8.0)

A user's installed beacon had NEVER self-updated. Three independent, all-load-bearing causes — fix
one and it still fails on the next:

- **The daily schedule was registered ONCE and never re-asserted → permanent death (#546).** The
  installer runs `dig-updater schedule install` exactly once; no pass re-registered it, so the
  moment the `\DIG\dig-updater` SYSTEM task went missing, NOTHING could ever wake a pass again.
  Fix: every full pass now `scheduler::ensure()`s its own schedule FIRST (before even the pause
  gate), re-registering a *provably absent* artifact. Self-heal is only meaningful because a pass
  triggered for ANY reason (a manual elevated run, the installer, a sibling tool) now resurrects the
  wake — a beacon that is already dead-and-never-invoked still needs one external kick.
- **`net session` is a false-negative elevation probe.** The old Windows elevation check shelled out
  to `net session`, which fails when the **Server (`LanmanServer`) service is stopped** — reporting
  "not elevated" from a genuinely-elevated console and blocking the scheduler's own registration.
  Replaced with the process token's real elevation state (`GetTokenInformation`/`TokenElevation`) —
  no external-service dependency. (Same trap would bite any DIG CLI that copied the `net session`
  idiom.)
- **`schtasks /Query` conflates ABSENT with ACCESS-DENIED.** Every non-zero exit was mapped to
  `installed:false`, so an ACL-locked-but-present task looked missing — which both lied to `schedule
  status` and would have driven the self-heal to needlessly recreate it. Presence is now TRISTATE
  (Registered / provably-Absent via `0x8004131F`/file-not-found / Unknown via `0x80070005`/"access is
  denied"); the self-heal re-registers ONLY provably-Absent. Default for an unrecognized (e.g.
  localized) failure stays Absent, so the common not-found case still self-heals.
- **feedsign signed the raw `.exe` but the broker installs dig-node via MSI → `msiexec` 1620 (#580).**
  The signer's platform table mapped Windows → `windows-x64.exe` for EVERY component, so dig-node's
  feed pointed at the raw PE; the broker staged those bytes as `dig-node.msi` and `msiexec /i`
  rejected the renamed PE (ERROR_INSTALL_PACKAGE_INVALID, 1620) and rolled back. dig-node's releases
  DO ship `-windows-x64.msi` / `-macos.pkg` / `_<ver>_amd64.deb` alongside the raw binaries — the
  feed just never selected them. Fix: a per-component `asset_kind` (raw_binary vs native_package) in
  `feed-config.json` drives the asset name; dig-node → the package, everything else stays raw. NOTE:
  the deb is the Debian convention `{prefix}_{ver}_amd64.deb` (underscores, no `linux` token) and the
  macOS pkg is ONE universal `{prefix}-{ver}-macos.pkg` (no arch) — both arches resolve to it. This
  fix needs a **feed RE-SIGN** to take effect (the on-disk signed manifest still points at the raw
  exe until `feed.yml` re-runs).
- **The install catalog hardcoded `C:\Program Files\DIG`, but the installer uses
  `%LOCALAPPDATA%\Programs\DigStore\bin` → updates landed in a phantom dir (#581).** The beacon
  "successfully" updated + health-verified a binary in a directory the user's binaries were NOT in,
  so the running binary never changed. Fix: the catalog derives its install root from the beacon's
  OWN `current_exe().parent()` — the universal installer drops every DIG binary (incl. `dig-updater`)
  in one bin dir, so components install as SIBLINGS of the running beacon, auto-matching wherever the
  installer put things with zero cross-repo path config. Falls back to the per-OS default only if
  `current_exe()` can't be resolved. This is the installer↔beacon install-root contract (SYSTEM.md).

## Unprivileged `check` UX + status truthfulness (#582, v0.8.1)

- **`std::fs::create_dir_all`'s "already exists" recovery can itself be access-denied, turning a
  benign collision into a bare, cryptic `os error 183`.** `CreateDirectory`/`mkdir` reports
  `ERROR_ALREADY_EXISTS` for a directory that is genuinely already there just as readily as for a
  real name collision; std's own recovery (`Path::is_dir()`) distinguishes the two by reading the
  path's metadata — but that read can ITSELF be access-denied when the existing directory is
  SYSTEM/Admin-owned (exactly what the hardened default state dir is), so the raw code propagates
  verbatim instead of a clean "already there" outcome. #540 only fixed the CI keystone (an explicit
  `$DIG_UPDATER_STATE_DIR` override); an everyday unprivileged `dig-updater check` with NO override
  still hit the Admin-only default and surfaced this as `rejected (staging_io_error): ... os error
  183` — a message with no actionable next step. Two independent, complementary fixes: (1)
  `dry_check_state_dir` now relocates to a per-user writable location
  (`%LOCALAPPDATA%\DIG\updater` / `$XDG_CACHE_HOME/dig-updater`) whenever the hardened default isn't
  actually usable — checked by ELEVATION first (cheap short-circuit) and, only when elevated, a REAL
  writability probe (an "elevated" console can still be denied by an unusual ACL); (2) the worker's
  own staging `create_dir_all` now tolerates `AlreadyExists` explicitly and proves usability with a
  real write, so even a directory that reaches the worker unusable degrades to an honest "not
  writable" detail instead of a bare OS error code. The install/full-pass path (`Broker::new`) is
  untouched — it stays pinned to the hardened default so anti-rollback can never be relocated.
- **A deterministic, portable stand-in for "this identity cannot use the directory": occupy the
  exact target PATH with a plain file.** Simulating a genuinely ACL-denied SYSTEM-owned directory
  needs real elevation/ACLs and doesn't run in ordinary CI. Writing a plain file at the directory's
  path instead reproduces the exact same `AlreadyExists`-on-`create_dir_all` outcome deterministically
  on every OS, with no privilege setup — the write-probe that follows then fails for its own reason
  (not a directory), proving the "clear detail, not a raw code" behavior without needing to fake
  elevation at all.
- **A persisted "installed" detail built from the PLAN (pre-install) rather than the post-install
  health probe silently drifts into a lie.** `Installer::apply_component`'s success arm used to
  report `pc.summary` — the version transition `Plan::build` predicted BEFORE the install ran — as
  the persisted `status.json` detail. The result TOKEN (`ComponentResult::Installed`) was always
  correct (it's only reached after `check_health` passes), but the STRING beside it was a stale
  prediction, not what the health gate had just re-observed running at `pc.dest`. Fix: `check_health`
  now returns the actually-detected `DetectedVersion` on success (not just `Ok(())`), and the success
  arm builds its detail from that ("dig-dns now reports dig-dns 0.13.0") instead of the plan summary.
  `last_check`/`last_check_kind` already timestamp every snapshot, so a reader can tell a persisted
  detail is only as current as that timestamp — no separate staleness field was needed.
- **An update "component" is a binary SET, not one file — and an MSI `/norestart` over a running
  service defers the swap SILENTLY (#666).** Two ways the beacon reported `Installed` while the
  update did not fully land: (A) a component ships byte-identical ALIASES (`digd≡dig-dns`,
  `digs≡digstore`, `dign≡dig-node`) written independently by the installer; the beacon modelled a
  component as a single `dest`, so it advanced the primary while the alias froze at its install-time
  version — invisible to the health probe, which only checked `dest`. Fix: `ComponentTarget`/
  `PlannedComponent` carry `aliases`; the raw-binary replace re-derives each alias by COPYING the
  just-verified PRIMARY bytes (never a re-fetch — the feed signs only the primary), and the health
  gate re-probes EVERY binary in the set. (B) dig-node runs as the OS service
  `net.dignetwork.dig-node`, which holds its binary open; `msiexec /i /qn /norestart` over that
  locked file returns SUCCESS but DEFERS the file swap to the next reboot (Windows "pending file
  rename"), so the post-install `--version` probe reads the STILL-OLD binary → health gate rolls it
  back every pass. Fix: a service-backed component is stopped (`sc stop` / `systemctl stop
  <derived-unit>` / `launchctl bootout`, absolute-path tools) BEFORE the replace and restarted after;
  the stop is a hard precondition (a failed stop defers, leaving the service running), and once
  stopped it is restarted in EVERY branch (success/defer/rollback) so it is never left down.
