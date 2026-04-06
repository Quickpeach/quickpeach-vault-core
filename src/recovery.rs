use thiserror::Error;

pub const RECOVERY_BUNDLE_FORMAT: &str = "quickpeach-recovery-bundle";
pub const RECOVERY_BUNDLE_VERSION: u32 = 1;
pub const RECOVERY_BUNDLE_HEADER: &str = "-----BEGIN QUICKPEACH RECOVERY BUNDLE-----";
pub const RECOVERY_BUNDLE_FOOTER: &str = "-----END QUICKPEACH RECOVERY BUNDLE-----";
pub const RECOVERY_KDF_ALGORITHM: &str = "argon2id";
pub const RECOVERY_ARGON2_MEMORY_KIB: u32 = 256 * 1024;
pub const RECOVERY_ARGON2_ITERATIONS: u32 = 3;
pub const RECOVERY_ARGON2_PARALLELISM: u32 = 4;
pub const RECOVERY_SALT_LEN: usize = 16;
pub const RECOVERY_PHRASE_WORD_COUNT: usize = 24;
pub const RECOVERY_AAD: &[u8] = b"quickpeach-recovery-bundle-v1";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RecoveryError {
    #[error("recovery phrase is invalid")]
    InvalidPhrase,
    #[error("recovery phrase must contain exactly {RECOVERY_PHRASE_WORD_COUNT} words")]
    InvalidPhraseLength,
    #[error("recovery phrase word verification failed")]
    VerificationFailed,
    #[error("argon2 parameters are invalid: {0}")]
    InvalidKdf(String),
    #[error("argon2 derivation failed: {0}")]
    Kdf(String),
    #[error("recovery bundle JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("recovery bundle format is not supported")]
    UnsupportedFormat,
    #[error("recovery bundle version is not supported")]
    UnsupportedVersion,
    #[error("recovery bundle key-derivation method is not supported")]
    UnsupportedKdf,
    #[error("recovery bundle salt is invalid: {0}")]
    InvalidSalt(String),
    #[error("recovery bundle footer is missing")]
    MissingFooter,
    #[error("vault envelope is invalid: {0}")]
    InvalidEnvelope(String),
    #[error("recovery bundle could not be opened with that recovery phrase: {0}")]
    Decrypt(String),
    #[error("recovery bundle payload is invalid: {0}")]
    InvalidPayload(String),
}

pub use crate::format::{
    DecodedRecoveryBundle, RecoveryBundleDocument, RecoveryBundleKdf, RecoveryPhraseCheckpoint,
};
pub use crate::primitives::kdf::{
    derive_recovery_wrap_key, generate_recovery_phrase, normalize_recovery_phrase,
    recovery_phrase_words, verify_recovery_phrase_checkpoints,
};
pub use crate::protocol::{
    build_recovery_bundle, encode_recovery_bundle_document, open_recovery_bundle,
    parse_recovery_bundle_document,
};

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct SamplePayload {
        created_at: String,
        value: String,
    }

    #[test]
    fn generates_normalized_24_word_phrase() {
        let phrase = generate_recovery_phrase().expect("phrase");
        let words = recovery_phrase_words(&phrase).expect("words");
        assert_eq!(words.len(), RECOVERY_PHRASE_WORD_COUNT);
        assert_eq!(
            normalize_recovery_phrase(&phrase).expect("normalized"),
            phrase
        );
    }

    #[test]
    fn verifies_phrase_checkpoints() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        verify_recovery_phrase_checkpoints(
            phrase,
            &[
                RecoveryPhraseCheckpoint {
                    index: 0,
                    word: "abandon".to_string(),
                },
                RecoveryPhraseCheckpoint {
                    index: 23,
                    word: "art".to_string(),
                },
            ],
        )
        .expect("checkpoints");
    }

    #[test]
    fn round_trips_recovery_bundle() {
        let phrase = generate_recovery_phrase().expect("phrase");
        let payload = SamplePayload {
            created_at: "2026-03-29T00:00:00Z".to_string(),
            value: "hello".to_string(),
        };

        let bundle = build_recovery_bundle(&payload, &phrase).expect("bundle");
        let decoded = open_recovery_bundle::<SamplePayload>(&bundle, &phrase).expect("decoded");
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.document.kdf.memory_kib, RECOVERY_ARGON2_MEMORY_KIB);
        assert_eq!(
            decoded.document.kdf.parallelism,
            RECOVERY_ARGON2_PARALLELISM
        );
    }
}
