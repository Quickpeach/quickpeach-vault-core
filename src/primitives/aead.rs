use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

use crate::{
    crypto::VaultCryptoError,
    format::{default_vault_algorithm, VaultEnvelope},
};

/// Encrypt `plaintext` with XChaCha20-Poly1305 using a random 24-byte nonce.
///
/// The `aad` is bound to the ciphertext via the Poly1305 tag — tampering
/// with either the ciphertext or the AAD will cause decryption to fail.
pub fn seal_with_key(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    key_version: u32,
) -> Result<VaultEnvelope, VaultCryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultCryptoError::Encrypt)?;

    Ok(VaultEnvelope {
        algorithm: default_vault_algorithm(),
        key_version,
        nonce,
        ciphertext,
    })
}

/// Decrypt a [`VaultEnvelope`] with XChaCha20-Poly1305.
///
/// Returns [`VaultCryptoError::UnsupportedAlgorithm`] if the envelope's
/// algorithm field is not `xchacha20poly1305`.
pub fn open_with_key(
    key: &[u8; 32],
    envelope: &VaultEnvelope,
    aad: &[u8],
) -> Result<Vec<u8>, VaultCryptoError> {
    if envelope.algorithm != crate::crypto::VAULT_ALGORITHM_XCHACHA20POLY1305 {
        return Err(VaultCryptoError::UnsupportedAlgorithm(
            envelope.algorithm.clone(),
        ));
    }

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultCryptoError::Decrypt)
}
