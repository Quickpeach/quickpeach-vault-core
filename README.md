# peachnote-vault-core

`peachnote-vault-core` is the shared MIT-licensed Rust crate for Peach Note's
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

## Not in scope

- raw key custody UX
- trusted-device enrollment
- recovery phrase flows
- live server sync/conflict handling

Those stay in the app/runtime layers.

