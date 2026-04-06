use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    crypto::VaultCryptoError,
    format::RecoveryPhraseCheckpoint,
    recovery::{RecoveryError, RECOVERY_PHRASE_WORD_COUNT},
};

/// Derive a 256-bit subkey from `root_key` using HKDF-SHA256.
///
/// The namespace is used as the HKDF salt, and the info string is
/// `peachnote/vault/{namespace}/{scope}/v{key_version}`. Both namespace
/// and scope are trimmed; scope is validated against `[a-zA-Z0-9._:/-]`.
///
/// The returned key is wrapped in [`Zeroizing`] and will be wiped on drop.
pub fn derive_namespaced_key(
    root_key: &[u8; 32],
    namespace: &str,
    scope: &str,
    key_version: u32,
) -> Result<Zeroizing<[u8; 32]>, VaultCryptoError> {
    if key_version == 0 {
        return Err(VaultCryptoError::InvalidKeyVersion);
    }
    let namespace = normalize_namespace(namespace)?;
    let scope = normalize_scope(scope)?;
    let hkdf = Hkdf::<Sha256>::new(Some(namespace.as_bytes()), root_key);
    let mut derived = Zeroizing::new([0u8; 32]);
    let info = format!("peachnote/vault/{namespace}/{scope}/v{key_version}");
    hkdf.expand(info.as_bytes(), &mut *derived)
        .map_err(|_| VaultCryptoError::KeyDerivation)?;
    Ok(derived)
}

/// Build the Additional Authenticated Data (AAD) bytes for a namespaced envelope.
///
/// Format: `peachnote-vault/v{ver}\0{namespace}\0{scope}\0{extra}`.
/// The extra bytes are optional and appended verbatim after the trailing null.
pub fn build_namespaced_aad(
    namespace: &str,
    scope: &str,
    key_version: u32,
    extra_aad: Option<&[u8]>,
) -> Result<Vec<u8>, VaultCryptoError> {
    if key_version == 0 {
        return Err(VaultCryptoError::InvalidKeyVersion);
    }
    let namespace = normalize_namespace(namespace)?;
    let scope = normalize_scope(scope)?;
    let mut aad = format!("peachnote-vault/v{key_version}\0{namespace}\0{scope}\0").into_bytes();
    if let Some(extra_aad) = extra_aad {
        aad.extend_from_slice(extra_aad);
    }
    Ok(aad)
}

/// Generate a new BIP-39 24-word recovery phrase from 256 bits of OS entropy.
pub fn generate_recovery_phrase() -> Result<String, RecoveryError> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).map_err(|_| RecoveryError::InvalidPhrase)?;
    Ok(mnemonic.to_string())
}

/// Validate and normalize a recovery phrase to canonical lowercase with single spaces.
/// Rejects phrases that aren't exactly 24 valid BIP-39 English words.
pub fn normalize_recovery_phrase(value: &str) -> Result<String, RecoveryError> {
    let mnemonic =
        Mnemonic::parse_in(Language::English, value).map_err(|_| RecoveryError::InvalidPhrase)?;
    if mnemonic.word_count() != RECOVERY_PHRASE_WORD_COUNT {
        return Err(RecoveryError::InvalidPhraseLength);
    }
    Ok(mnemonic.to_string())
}

/// Split a recovery phrase into its individual words after normalization.
pub fn recovery_phrase_words(value: &str) -> Result<Vec<String>, RecoveryError> {
    let normalized = normalize_recovery_phrase(value)?;
    Ok(normalized
        .split_whitespace()
        .map(ToString::to_string)
        .collect())
}

/// Verify that specific words at given indices match the recovery phrase.
/// Comparison is case-insensitive. Used for UI confirmation flows.
pub fn verify_recovery_phrase_checkpoints(
    phrase: &str,
    checkpoints: &[RecoveryPhraseCheckpoint],
) -> Result<(), RecoveryError> {
    let words = recovery_phrase_words(phrase)?;
    for checkpoint in checkpoints {
        let expected = words
            .get(checkpoint.index)
            .ok_or(RecoveryError::VerificationFailed)?;
        if expected != &checkpoint.word.trim().to_lowercase() {
            return Err(RecoveryError::VerificationFailed);
        }
    }
    Ok(())
}

/// Derive a 256-bit wrap key from a recovery phrase using Argon2id.
///
/// The returned key is wrapped in [`Zeroizing`] and will be wiped on drop.
/// This is deliberately slow (~2-5 seconds) to resist brute-force attacks.
pub fn derive_recovery_wrap_key(
    phrase: &str,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>, RecoveryError> {
    let normalized = normalize_recovery_phrase(phrase)?;
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|error| RecoveryError::InvalidKdf(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(normalized.as_bytes(), salt, &mut *derived)
        .map_err(|error| RecoveryError::Kdf(error.to_string()))?;
    Ok(derived)
}

fn normalize_namespace(namespace: &str) -> Result<&str, VaultCryptoError> {
    let trimmed = namespace.trim();
    if trimmed.is_empty() {
        return Err(VaultCryptoError::EmptyNamespace);
    }
    Ok(trimmed)
}

fn normalize_scope(scope: &str) -> Result<&str, VaultCryptoError> {
    let trimmed = scope.trim();
    if trimmed.is_empty() {
        return Err(VaultCryptoError::EmptyScope);
    }
    if trimmed.len() > 128 {
        return Err(VaultCryptoError::ScopeTooLong);
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-' | '/'))
    {
        return Err(VaultCryptoError::InvalidScope);
    }
    Ok(trimmed)
}
