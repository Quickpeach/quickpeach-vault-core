# QuickPeach Vault Core

`peachnote-vault-core` is the shared MIT-licensed Rust crate for QuickPeach's
vault format, manifest types, and encryption primitives.

It is intentionally smaller than the Tauri app:

- no OS keychain integration
- no Stronghold wiring
- no sync queue orchestration
- no plugin sandbox/runtime logic

It is the reusable, auditable core that both the app host and future external
tools can depend on.

## Current scope

- chunk and object manifest structs
- XChaCha20-Poly1305 envelope sealing/opening
- HKDF-derived scoped keys
- base64 transport envelope helpers

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

## Not in scope

- raw key custody UX
- trusted-device enrollment
- recovery phrase flows
- live server sync/conflict handling

Those stay in the app/runtime layers.
