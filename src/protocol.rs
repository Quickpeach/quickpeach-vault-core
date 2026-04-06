use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    crypto::VaultCryptoError,
    format::{
        decode_envelope, decode_recovery_bundle_binary, encode_envelope,
        encode_recovery_bundle_binary, DecodedRecoveryBundle, RecoveryBundleDocument,
        RecoveryBundleKdf, VaultEnvelope,
    },
    primitives::{
        aead::{open_with_key, seal_with_key},
        kdf::{build_namespaced_aad, derive_namespaced_key, derive_recovery_wrap_key},
    },
    recovery::{
        RecoveryError, RECOVERY_AAD, RECOVERY_ARGON2_ITERATIONS, RECOVERY_ARGON2_MEMORY_KIB,
        RECOVERY_ARGON2_PARALLELISM, RECOVERY_BUNDLE_FOOTER, RECOVERY_BUNDLE_FORMAT,
        RECOVERY_BUNDLE_HEADER, RECOVERY_BUNDLE_VERSION, RECOVERY_KDF_ALGORITHM, RECOVERY_SALT_LEN,
    },
};

/// Derive a subkey from `root_key` for the given namespace/scope, then encrypt `plaintext`.
///
/// This is the primary encrypt entry point — it composes key derivation, AAD
/// construction, and XChaCha20-Poly1305 encryption in a single call.
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

/// Derive a subkey from `root_key` for the given namespace/scope, then decrypt `envelope`.
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

/// Serialize a [`RecoveryBundleDocument`] to PEM with a binary payload.
///
/// The output follows real PEM convention: the data between the header and
/// footer is base64-encoded binary (not JSON). The binary layout is documented
/// in `format.rs`.
pub fn encode_recovery_bundle_document(
    document: &RecoveryBundleDocument,
) -> Result<String, RecoveryError> {
    let envelope = decode_envelope(&document.envelope)
        .map_err(|e| RecoveryError::InvalidEnvelope(e.to_string()))?;
    let binary = encode_recovery_bundle_binary(document, &envelope)?;
    let b64 = BASE64_STANDARD.encode(&binary);

    // wrap at 76 chars per line (PEM standard, RFC 7468)
    let mut pem = String::with_capacity(
        RECOVERY_BUNDLE_HEADER.len() + b64.len() + RECOVERY_BUNDLE_FOOTER.len() + 64,
    );
    pem.push_str(RECOVERY_BUNDLE_HEADER);
    pem.push('\n');
    for chunk in b64.as_bytes().chunks(76) {
        // SAFETY: base64 output is always valid ASCII, so this cannot fail.
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is valid ASCII"));
        pem.push('\n');
    }
    pem.push_str(RECOVERY_BUNDLE_FOOTER);
    Ok(pem)
}

/// Parse a recovery bundle into a [`RecoveryBundleDocument`].
///
/// Accepts both the current binary PEM format and legacy JSON (with or
/// without PEM armor) for backward compatibility.
pub fn parse_recovery_bundle_document(
    value: &str,
) -> Result<RecoveryBundleDocument, RecoveryError> {
    let trimmed = value.trim();

    if let Some(inner) = trimmed.strip_prefix(RECOVERY_BUNDLE_HEADER) {
        let inner = inner.trim();
        let inner = inner
            .strip_suffix(RECOVERY_BUNDLE_FOOTER)
            .ok_or(RecoveryError::MissingFooter)?;
        let inner = inner.trim();

        // try binary PEM first (base64 → bytes → decode binary)
        if let Ok(bytes) = BASE64_STANDARD.decode(inner.replace('\n', "").replace('\r', "")) {
            if bytes.starts_with(b"QPRB") {
                let (doc, _) = decode_recovery_bundle_binary(&bytes)?;
                return Ok(doc);
            }
        }

        // fall back to legacy JSON-inside-PEM
        let document: RecoveryBundleDocument =
            serde_json::from_str(inner).map_err(|e| RecoveryError::InvalidJson(e.to_string()))?;
        return validate_document(document);
    }

    // no PEM header — try raw JSON (legacy compat)
    let document: RecoveryBundleDocument =
        serde_json::from_str(trimmed).map_err(|e| RecoveryError::InvalidJson(e.to_string()))?;
    validate_document(document)
}

fn validate_document(
    document: RecoveryBundleDocument,
) -> Result<RecoveryBundleDocument, RecoveryError> {
    if document.format != RECOVERY_BUNDLE_FORMAT {
        return Err(RecoveryError::UnsupportedFormat);
    }
    if document.version != RECOVERY_BUNDLE_VERSION {
        return Err(RecoveryError::UnsupportedVersion);
    }
    if document.kdf.algorithm != RECOVERY_KDF_ALGORITHM {
        return Err(RecoveryError::UnsupportedKdf);
    }
    Ok(document)
}

/// Create a complete recovery bundle.
///
/// Flow: serialize payload → Argon2id key derivation → XChaCha20-Poly1305
/// encryption → binary encoding → base64 → PEM armor.
pub fn build_recovery_bundle<T: Serialize>(
    payload: &T,
    phrase: &str,
) -> Result<String, RecoveryError> {
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|error| RecoveryError::InvalidPayload(error.to_string()))?;
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let wrap_key = derive_recovery_wrap_key(
        phrase,
        &salt,
        RECOVERY_ARGON2_MEMORY_KIB,
        RECOVERY_ARGON2_ITERATIONS,
        RECOVERY_ARGON2_PARALLELISM,
    )?;
    let envelope: VaultEnvelope = seal_with_key(
        &wrap_key,
        &payload_bytes,
        RECOVERY_AAD,
        RECOVERY_BUNDLE_VERSION,
    )
    .map_err(|error| RecoveryError::InvalidEnvelope(error.to_string()))?;

    let document = RecoveryBundleDocument {
        format: RECOVERY_BUNDLE_FORMAT.to_string(),
        version: RECOVERY_BUNDLE_VERSION,
        kdf: RecoveryBundleKdf {
            algorithm: RECOVERY_KDF_ALGORITHM.to_string(),
            salt_base64: BASE64_STANDARD.encode(salt),
            memory_kib: RECOVERY_ARGON2_MEMORY_KIB,
            iterations: RECOVERY_ARGON2_ITERATIONS,
            parallelism: RECOVERY_ARGON2_PARALLELISM,
        },
        envelope: encode_envelope(&envelope),
    };

    encode_recovery_bundle_document(&document)
}

/// Open a recovery bundle with a BIP-39 phrase.
///
/// Handles both binary PEM (current) and legacy JSON formats. Flow:
/// parse PEM → decode binary → Argon2id → XChaCha20-Poly1305 decrypt → deserialize.
pub fn open_recovery_bundle<T: DeserializeOwned>(
    bundle: &str,
    phrase: &str,
) -> Result<DecodedRecoveryBundle<T>, RecoveryError> {
    let document = parse_recovery_bundle_document(bundle)?;
    let salt = BASE64_STANDARD
        .decode(document.kdf.salt_base64.as_bytes())
        .map_err(|error| RecoveryError::InvalidSalt(error.to_string()))?;
    let wrap_key = derive_recovery_wrap_key(
        phrase,
        &salt,
        document.kdf.memory_kib,
        document.kdf.iterations,
        document.kdf.parallelism,
    )?;
    let envelope = decode_envelope(&document.envelope)
        .map_err(|error| RecoveryError::InvalidEnvelope(error.to_string()))?;
    let plaintext = open_with_key(&wrap_key, &envelope, RECOVERY_AAD)
        .map_err(|error| RecoveryError::Decrypt(error.to_string()))?;
    let payload = serde_json::from_slice(&plaintext)
        .map_err(|error| RecoveryError::InvalidPayload(error.to_string()))?;
    Ok(DecodedRecoveryBundle { document, payload })
}
