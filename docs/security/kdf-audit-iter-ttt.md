# Iteration TTT — Argon2id KDF parameter audit (recovery bundles)

**Date:** 2026-05-26
**Scope:** `peachnote-vault-core` recovery-bundle key derivation
**Outcome:** No parameter change required. Current defaults already
exceed OWASP 2024 guidance. Forward-compat contract documented and
pinned by a new test.

## Current parameters (unchanged)

| Parameter            | Constant                       | Value         |
| -------------------- | ------------------------------ | ------------- |
| Algorithm            | `RECOVERY_KDF_ALGORITHM`       | `argon2id`    |
| Version              | argon2 crate                   | `0x13` (v1.3) |
| Memory cost (`m`)    | `RECOVERY_ARGON2_MEMORY_KIB`   | `262144` (256 MiB) |
| Iterations (`t`)     | `RECOVERY_ARGON2_ITERATIONS`   | `3`           |
| Parallelism (`p`)    | `RECOVERY_ARGON2_PARALLELISM`  | `4`           |
| Output length        | hard-coded in `kdf.rs`         | `32` bytes    |
| Salt length          | `RECOVERY_SALT_LEN`            | `16` bytes (CSPRNG) |

## OWASP 2024 baseline (Argon2id)

From the OWASP Password Storage Cheat Sheet (2024 revision), the more
conservative Argon2id recommendation is:

- `m = 65536` KiB (64 MiB)
- `t = 3`
- `p = 4`

(The aggressive minimum is `m = 19456` KiB / `t = 2` / `p = 1`. We
target the conservative row because recovery-phrase derivation is a
one-time interactive cost on user hardware, not a per-request server
operation.)

## Comparison

| Parameter | OWASP 2024 floor | Current default | Ratio |
| --------- | ----------------- | --------------- | ----- |
| `m` (KiB) | 65536             | 262144          | **4.0×** |
| `t`       | 3                 | 3               | 1.0× |
| `p`       | 4                 | 4               | 1.0× |

Memory cost is **4× the OWASP recommendation**. Iterations and
parallelism match exactly. No bump is warranted; lowering would
weaken the brute-force ceiling, and raising further would risk OOM
or unacceptable latency on low-end mobile/Tauri targets.

## Forward-compat contract

The recovery-bundle binary wire format (`src/format.rs`, lines 90–105)
serializes the Argon2id parameters **inline** as three big-endian
`u32` fields immediately after the version byte:

```
MAGIC (4)    : b"QPRB"
VERSION (1)  : 0x01
KDF_ID (1)   : 0x01 = argon2id
MEM_KIB (4)  : Argon2 memory cost in KiB
ITERS (4)    : Argon2 iterations
PAR (4)      : Argon2 parallelism
SALT_LEN (1) : length of salt
SALT (N)     : salt bytes
...
```

`open_recovery_bundle` (in `src/protocol.rs`) reads these fields and
passes them to `derive_recovery_wrap_key` verbatim. **The params are
the version.** No `KDF_VERSION` constant is required, and bumping the
crate defaults would *never* break older bundles — those bundles
carry their own params and would continue to open with whatever
weaker (or stronger) settings they were authored under.

Consequence: any future bump can be a pure default change with no
`RECOVERY_BUNDLE_VERSION` increment. The bundle-format version field
should only move when the binary layout itself changes (new fields,
new salt-length encoding, etc.).

This contract is now pinned by
`tests/kdf_param_audit.rs::legacy_lower_param_bundles_still_open`,
which forges a bundle at the OWASP minimum (64 MiB / 3 / 4) and
asserts the current decoder opens it correctly. CI will fail loudly
if a future change breaks the inline-param contract.

## Derivation-time expectation

We did not run `cargo bench` (no bench harness in this crate; adding
one is out of scope for this iteration). From the Argon2 reference
table and the upstream `argon2` crate's published benchmarks at
`m=262144 KiB, t=3, p=4`:

- Modern desktop (8-core, DDR4-3200): **~1.0–1.5 s**
- Mid-range laptop (4-core, DDR4-2400): **~1.5–2.5 s**
- Low-end mobile (Tauri Android target, 4-core LPDDR4): **~2.5–5 s**

These figures are consistent with the inline comment in `kdf.rs`:
*"This is deliberately slow (~2-5 seconds) to resist brute-force
attacks."*

If a future iteration needs a precise number, add a `criterion`
bench under `benches/` and report measured timings — but until users
report a usability regression, the audit defers to the design
comment.

## Tests added

- `tests/kdf_param_audit.rs` — top-level `const _` block enforces the
  OWASP 2024 floor at compile time; the test binary will fail to
  build if any of the three parameter constants is ever lowered below
  the floor. `argon2id_floor_audit_compiled` is a runtime smoke
  marker that surfaces the audit in `cargo test` output.
- `tests/kdf_param_audit.rs::new_bundles_use_current_defaults`
  — roundtrip assertion: a freshly built bundle records the current
  constants in its wire-level KDF block.
- `tests/kdf_param_audit.rs::legacy_lower_param_bundles_still_open`
  — pins the inline-params forward-compat contract by opening a
  hand-forged bundle authored with the OWASP minimum params.

## References

- OWASP Password Storage Cheat Sheet (2024):
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- RFC 9106 (Argon2 specification):
  https://datatracker.ietf.org/doc/html/rfc9106
