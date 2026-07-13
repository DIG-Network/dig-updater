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
