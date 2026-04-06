#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

mod format;
mod primitives;
mod protocol;

pub mod crypto;
pub mod manifest;
pub mod recovery;

pub use crypto::{
    build_namespaced_aad, decode_envelope, derive_namespaced_key, encode_envelope, open_namespaced,
    open_with_key, seal_namespaced, seal_with_key, EncodedVaultEnvelope, VaultCryptoError,
    VaultEnvelope, VAULT_ALGORITHM_XCHACHA20POLY1305,
};
pub use manifest::{
    manifest_hash_eq, manifest_hash_hex, VaultChunkDescriptor, VaultManifest, VaultManifestKind,
};
pub use recovery::{
    build_recovery_bundle, derive_recovery_wrap_key, encode_recovery_bundle_document,
    generate_recovery_phrase, normalize_recovery_phrase, open_recovery_bundle,
    parse_recovery_bundle_document, recovery_phrase_words, verify_recovery_phrase_checkpoints,
    DecodedRecoveryBundle, RecoveryBundleDocument, RecoveryBundleKdf, RecoveryError,
    RecoveryPhraseCheckpoint, RECOVERY_AAD, RECOVERY_ARGON2_ITERATIONS, RECOVERY_ARGON2_MEMORY_KIB,
    RECOVERY_ARGON2_PARALLELISM, RECOVERY_BUNDLE_FOOTER, RECOVERY_BUNDLE_FORMAT,
    RECOVERY_BUNDLE_HEADER, RECOVERY_BUNDLE_VERSION, RECOVERY_KDF_ALGORITHM,
    RECOVERY_PHRASE_WORD_COUNT, RECOVERY_SALT_LEN,
};
pub use zeroize::Zeroizing;
