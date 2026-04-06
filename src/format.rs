use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::crypto::{VaultCryptoError, VAULT_ALGORITHM_XCHACHA20POLY1305};
use crate::recovery::RecoveryError;

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

/// Convert a [`VaultEnvelope`] (binary) to its base64-encoded transport form.
pub fn encode_envelope(envelope: &VaultEnvelope) -> EncodedVaultEnvelope {
    EncodedVaultEnvelope {
        algorithm: envelope.algorithm.clone(),
        key_version: envelope.key_version,
        nonce_base64: BASE64_STANDARD.encode(envelope.nonce),
        ciphertext_base64: BASE64_STANDARD.encode(&envelope.ciphertext),
    }
}

/// Decode a base64-encoded transport envelope back to its binary [`VaultEnvelope`].
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

pub(crate) fn default_vault_algorithm() -> String {
    VAULT_ALGORITHM_XCHACHA20POLY1305.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryBundleKdf {
    pub algorithm: String,
    pub salt_base64: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryBundleDocument {
    pub format: String,
    pub version: u32,
    pub kdf: RecoveryBundleKdf,
    pub envelope: EncodedVaultEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecoveryBundle<T> {
    pub document: RecoveryBundleDocument,
    pub payload: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryPhraseCheckpoint {
    pub index: usize,
    pub word: String,
}

// -- binary wire format for recovery bundles --
//
// Layout (all multi-byte integers are big-endian):
//
//   MAGIC (4)  : b"QPRB"
//   VERSION (1): 0x01
//   KDF_ID (1) : 0x01 = argon2id
//   MEM_KIB (4): Argon2 memory cost in KiB
//   ITERS (4)  : Argon2 iterations
//   PAR (4)    : Argon2 parallelism
//   SALT_LEN(1): length of salt
//   SALT (N)   : salt bytes
//   AEAD_ID (1): 0x01 = xchacha20poly1305
//   KEY_VER (4): key version
//   NONCE (24) : XChaCha20 nonce
//   CIPHERTEXT : remaining bytes (plaintext + 16-byte Poly1305 tag)

pub(crate) const BUNDLE_MAGIC: &[u8; 4] = b"QPRB";
pub(crate) const BUNDLE_VERSION_1: u8 = 0x01;
pub(crate) const KDF_ARGON2ID: u8 = 0x01;
pub(crate) const AEAD_XCHACHA20POLY1305: u8 = 0x01;

/// Serialize a [`RecoveryBundleDocument`] to the binary wire format.
pub(crate) fn encode_recovery_bundle_binary(
    doc: &RecoveryBundleDocument,
    envelope: &VaultEnvelope,
) -> Result<Vec<u8>, RecoveryError> {
    let salt = BASE64_STANDARD
        .decode(doc.kdf.salt_base64.as_bytes())
        .map_err(|e| RecoveryError::InvalidSalt(e.to_string()))?;

    if salt.len() > 255 {
        return Err(RecoveryError::InvalidSalt("salt too long".into()));
    }

    let mut buf = Vec::with_capacity(64 + envelope.ciphertext.len());

    // header
    buf.extend_from_slice(BUNDLE_MAGIC);
    buf.push(BUNDLE_VERSION_1);

    // kdf params
    buf.push(KDF_ARGON2ID);
    buf.extend_from_slice(&doc.kdf.memory_kib.to_be_bytes());
    buf.extend_from_slice(&doc.kdf.iterations.to_be_bytes());
    buf.extend_from_slice(&doc.kdf.parallelism.to_be_bytes());
    buf.push(salt.len() as u8);
    buf.extend_from_slice(&salt);

    // aead params + payload
    buf.push(AEAD_XCHACHA20POLY1305);
    buf.extend_from_slice(&envelope.key_version.to_be_bytes());
    buf.extend_from_slice(&envelope.nonce);
    buf.extend_from_slice(&envelope.ciphertext);

    Ok(buf)
}

/// Deserialize the binary wire format back to a [`RecoveryBundleDocument`] and [`VaultEnvelope`].
pub(crate) fn decode_recovery_bundle_binary(
    data: &[u8],
) -> Result<(RecoveryBundleDocument, VaultEnvelope), RecoveryError> {
    use crate::recovery::{
        RECOVERY_BUNDLE_FORMAT, RECOVERY_BUNDLE_VERSION, RECOVERY_KDF_ALGORITHM,
    };

    let mut pos = 0;

    let read = |pos: &mut usize, n: usize| -> Result<&[u8], RecoveryError> {
        if *pos + n > data.len() {
            return Err(RecoveryError::InvalidPayload("truncated bundle".into()));
        }
        let slice = &data[*pos..*pos + n];
        *pos += n;
        Ok(slice)
    };

    let read_u8 = |pos: &mut usize| -> Result<u8, RecoveryError> { Ok(read(pos, 1)?[0]) };

    let read_u32 = |pos: &mut usize| -> Result<u32, RecoveryError> {
        let bytes: [u8; 4] = read(pos, 4)?
            .try_into()
            .map_err(|_| RecoveryError::InvalidPayload("bad u32".into()))?;
        Ok(u32::from_be_bytes(bytes))
    };

    // magic
    let magic = read(&mut pos, 4)?;
    if magic != BUNDLE_MAGIC {
        return Err(RecoveryError::UnsupportedFormat);
    }

    // version
    let version = read_u8(&mut pos)?;
    if version != BUNDLE_VERSION_1 {
        return Err(RecoveryError::UnsupportedVersion);
    }

    // kdf
    let kdf_id = read_u8(&mut pos)?;
    if kdf_id != KDF_ARGON2ID {
        return Err(RecoveryError::UnsupportedKdf);
    }
    let memory_kib = read_u32(&mut pos)?;
    let iterations = read_u32(&mut pos)?;
    let parallelism = read_u32(&mut pos)?;
    let salt_len = read_u8(&mut pos)? as usize;
    let salt = read(&mut pos, salt_len)?.to_vec();

    // aead
    let aead_id = read_u8(&mut pos)?;
    if aead_id != AEAD_XCHACHA20POLY1305 {
        return Err(RecoveryError::InvalidEnvelope(
            "unsupported AEAD algorithm".into(),
        ));
    }
    let key_version = read_u32(&mut pos)?;
    let nonce: [u8; 24] = read(&mut pos, 24)?
        .try_into()
        .map_err(|_| RecoveryError::InvalidEnvelope("bad nonce".into()))?;
    let ciphertext = data[pos..].to_vec();

    if ciphertext.len() < 16 {
        return Err(RecoveryError::InvalidEnvelope(
            "ciphertext too short for Poly1305 tag".into(),
        ));
    }

    let doc = RecoveryBundleDocument {
        format: RECOVERY_BUNDLE_FORMAT.to_string(),
        version: RECOVERY_BUNDLE_VERSION,
        kdf: RecoveryBundleKdf {
            algorithm: RECOVERY_KDF_ALGORITHM.to_string(),
            salt_base64: BASE64_STANDARD.encode(&salt),
            memory_kib,
            iterations,
            parallelism,
        },
        envelope: EncodedVaultEnvelope {
            algorithm: VAULT_ALGORITHM_XCHACHA20POLY1305.to_string(),
            key_version,
            nonce_base64: BASE64_STANDARD.encode(nonce),
            ciphertext_base64: BASE64_STANDARD.encode(&ciphertext),
        },
    };

    let envelope = VaultEnvelope {
        algorithm: VAULT_ALGORITHM_XCHACHA20POLY1305.to_string(),
        key_version,
        nonce,
        ciphertext,
    };

    Ok((doc, envelope))
}
