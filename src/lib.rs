pub mod crypto;
pub mod manifest;

pub use crypto::{
    build_namespaced_aad, decode_envelope, derive_namespaced_key, encode_envelope,
    open_namespaced, open_with_key, seal_namespaced, seal_with_key, EncodedVaultEnvelope,
    VaultCryptoError, VaultEnvelope, VAULT_ALGORITHM_XCHACHA20POLY1305,
};
pub use manifest::{
    manifest_hash_hex, VaultChunkDescriptor, VaultManifest, VaultManifestKind,
};

