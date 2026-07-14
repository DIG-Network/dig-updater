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
  in `release.yml` declares `shell: bash`.
