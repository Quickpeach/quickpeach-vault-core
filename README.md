# QuickPeach Vault Core

`peachnote-vault-core` is the shared MIT-licensed Rust crate for QuickPeach's
vault format, manifest types, and encryption primitives.

It is the reusable, auditable core that both the app host and future external
tools can depend on.

## Current scope

- chunk and object manifest structs
- XChaCha20-Poly1305 envelope sealing/opening
- HKDF-derived scoped keys
- base64 transport envelope helpers

## Quality Standards

The library now treats these as the normal baseline before release:

- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- `cargo check --manifest-path fuzz/Cargo.toml`

The repo also includes:

- adversarial crypto and recovery tests under `tests/`
- compatibility fixtures for frozen v1 behavior under `tests/fixtures/compat/`
- libFuzzer targets under [`fuzz/README.md`](/Users/pantakan/tida/peachnote-vault-core/fuzz/README.md)
- KDF parameter audit notes under [`docs/security/`](docs/security/kdf-audit-iter-ttt.md)

## Recovery-bundle KDF parameters

Recovery bundles derive their wrap key with Argon2id v1.3 at
`m = 262144 KiB (256 MiB)`, `t = 3`, `p = 4`, with a 16-byte CSPRNG
salt. These exceed OWASP 2024 guidance (64 MiB / 3 / 4) by 4× on
memory. The binary wire format carries the KDF parameters inline,
so any future bump applies only to newly issued bundles — older
bundles remain openable indefinitely. See
[`docs/security/kdf-audit-iter-ttt.md`](docs/security/kdf-audit-iter-ttt.md)
for the full audit, derivation-time expectations, and the
forward-compat contract.

To regenerate compatibility fixtures intentionally:

```bash
cargo test --test generate_compat_fixtures -- --ignored --nocapture
```

## Add it to your project

This is a Rust library crate, so consumers normally add it as a dependency with
`cargo add`, not `cargo install`.

### Git dependency

```bash
cargo add peachnote-vault-core --git https://github.com/Quickpeach/quickpeach-vault-core.git
```

### Cargo.toml

```toml
[dependencies]
peachnote-vault-core = { git = "https://github.com/Quickpeach/quickpeach-vault-core.git" }
```

Today, the public install path is the Git repo. A crates.io release can be
layered on top later without changing the crate API.
