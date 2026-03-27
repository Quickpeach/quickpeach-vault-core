use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

pub const VAULT_ALGORITHM_XCHACHA20POLY1305: &str = "xchacha20poly1305";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEnvelope {
    pub algorithm: String,
    pub key_version: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncodedVaultEnvelope {
    pub algorithm: String,
    pub key_version: u32,
    pub nonce_base64: String,
    pub ciphertext_base64: String,
}

#[derive(Debug, Error)]
pub enum VaultCryptoError {
    #[error("namespace must not be empty")]
    EmptyNamespace,
    #[error("scope must not be empty")]
    EmptyScope,
    #[error("scope is too long")]
    ScopeTooLong,
    #[error("scope contains unsupported characters")]
    InvalidScope,
    #[error("unsupported vault algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    #[error("invalid envelope nonce length")]
    InvalidNonceLength,
    #[error("invalid base64 envelope field: {0}")]
    InvalidBase64(String),
    #[error("hkdf expansion failed")]
    KeyDerivation,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

pub fn derive_namespaced_key(
    root_key: &[u8; 32],
    namespace: &str,
    scope: &str,
    key_version: u32,
) -> Result<[u8; 32], VaultCryptoError> {
    let namespace = normalize_namespace(namespace)?;
    let scope = normalize_scope(scope)?;
    let hkdf = Hkdf::<Sha256>::new(Some(namespace.as_bytes()), root_key);
    let mut derived = [0u8; 32];
    let info = format!("peachnote/vault/{namespace}/{scope}/v{key_version}");
    hkdf.expand(info.as_bytes(), &mut derived)
        .map_err(|_| VaultCryptoError::KeyDerivation)?;
    Ok(derived)
}

pub fn build_namespaced_aad(
    namespace: &str,
    scope: &str,
    key_version: u32,
    extra_aad: Option<&[u8]>,
) -> Result<Vec<u8>, VaultCryptoError> {
    let namespace = normalize_namespace(namespace)?;
    let scope = normalize_scope(scope)?;
    let mut aad = format!("peachnote-vault/v{key_version}\0{namespace}\0{scope}\0").into_bytes();
    if let Some(extra_aad) = extra_aad {
        aad.extend_from_slice(extra_aad);
    }
    Ok(aad)
}

pub fn seal_with_key(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    key_version: u32,
) -> Result<VaultEnvelope, VaultCryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: plaintext, aad },
        )
        .map_err(|_| VaultCryptoError::Encrypt)?;

    Ok(VaultEnvelope {
        algorithm: VAULT_ALGORITHM_XCHACHA20POLY1305.to_string(),
        key_version,
        nonce,
        ciphertext,
    })
}

pub fn open_with_key(
    key: &[u8; 32],
    envelope: &VaultEnvelope,
    aad: &[u8],
) -> Result<Vec<u8>, VaultCryptoError> {
    if envelope.algorithm != VAULT_ALGORITHM_XCHACHA20POLY1305 {
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

pub fn seal_namespaced(
    root_key: &[u8; 32],
    namespace: &str,
    scope: &str,
    plaintext: &[u8],
    extra_aad: Option<&[u8]>,
    key_version: u32,
) -> Result<VaultEnvelope, VaultCryptoError> {
    let key = derive_namespaced_key(root_key, namespace, scope, key_version)?;
    let aad = build_namespaced_aad(namespace, scope, key_version, extra_aad)?;
    seal_with_key(&key, plaintext, &aad, key_version)
}

pub fn open_namespaced(
    root_key: &[u8; 32],
    namespace: &str,
    scope: &str,
    envelope: &VaultEnvelope,
    extra_aad: Option<&[u8]>,
) -> Result<Vec<u8>, VaultCryptoError> {
    let key = derive_namespaced_key(root_key, namespace, scope, envelope.key_version)?;
    let aad = build_namespaced_aad(namespace, scope, envelope.key_version, extra_aad)?;
    open_with_key(&key, envelope, &aad)
}

pub fn encode_envelope(envelope: &VaultEnvelope) -> EncodedVaultEnvelope {
    EncodedVaultEnvelope {
        algorithm: envelope.algorithm.clone(),
        key_version: envelope.key_version,
        nonce_base64: BASE64_STANDARD.encode(envelope.nonce),
        ciphertext_base64: BASE64_STANDARD.encode(&envelope.ciphertext),
    }
}

pub fn decode_envelope(envelope: &EncodedVaultEnvelope) -> Result<VaultEnvelope, VaultCryptoError> {
    let nonce = BASE64_STANDARD
        .decode(envelope.nonce_base64.as_bytes())
        .map_err(|error| VaultCryptoError::InvalidBase64(error.to_string()))?;
    let ciphertext = BASE64_STANDARD
        .decode(envelope.ciphertext_base64.as_bytes())
        .map_err(|error| VaultCryptoError::InvalidBase64(error.to_string()))?;

    Ok(VaultEnvelope {
        algorithm: envelope.algorithm.clone(),
        key_version: envelope.key_version,
        nonce: nonce
            .try_into()
            .map_err(|_| VaultCryptoError::InvalidNonceLength)?,
        ciphertext,
    })
}

fn normalize_namespace(namespace: &str) -> Result<String, VaultCryptoError> {
    let trimmed = namespace.trim();
    if trimmed.is_empty() {
        return Err(VaultCryptoError::EmptyNamespace);
    }
    Ok(trimmed.to_string())
}

fn normalize_scope(scope: &str) -> Result<String, VaultCryptoError> {
    let trimmed = scope.trim();
    if trimmed.is_empty() {
        return Err(VaultCryptoError::EmptyScope);
    }
    if trimmed.len() > 128 {
        return Err(VaultCryptoError::ScopeTooLong);
    }
    if !trimmed
        .chars()
        .all(|char| char.is_ascii_alphanumeric() || matches!(char, '.' | ':' | '_' | '-' | '/'))
    {
        return Err(VaultCryptoError::InvalidScope);
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_namespaced_envelope() {
        let root_key = [7u8; 32];
        let aad = b"metadata";
        let envelope = seal_namespaced(
            &root_key,
            "extension.demo",
            "storage/blob",
            b"hello world",
            Some(aad),
            1,
        )
        .expect("seal");

        let opened = open_namespaced(
            &root_key,
            "extension.demo",
            "storage/blob",
            &envelope,
            Some(aad),
        )
        .expect("open");

        assert_eq!(opened, b"hello world");
    }

    #[test]
    fn encodes_and_decodes_transport_envelope() {
        let root_key = [9u8; 32];
        let envelope = seal_namespaced(
            &root_key,
            "extension.demo",
            "storage/blob",
            b"bytes",
            None,
            1,
        )
        .expect("seal");

        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).expect("decode");

        assert_eq!(decoded, envelope);
    }
}

