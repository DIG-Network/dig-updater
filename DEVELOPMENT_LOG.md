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
