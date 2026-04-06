use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultManifestKind {
    Note,
    Attachment,
    Palette,
    ExtensionStorage,
    ExtensionSyncState,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultChunkDescriptor {
    pub chunk_id: String,
    pub plaintext_byte_size: u64,
    pub ciphertext_byte_size: u64,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultManifest {
    pub object_kind: VaultManifestKind,
    pub object_id: String,
    pub object_version: u64,
    #[serde(default)]
    pub manifest_hash: Option<String>,
    #[serde(default)]
    pub previous_manifest_hash: Option<String>,
    pub content_hash: String,
    pub key_version: u32,
    pub updated_at: String,
    pub chunks: Vec<VaultChunkDescriptor>,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultManifestError {
    #[error("manifest serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Compute a SHA-256 hash of the manifest's canonical JSON representation.
///
/// The `manifest_hash` field should be `None` when computing the hash to
/// avoid self-referential hashing. The result is lowercase hex, 64 characters.
pub fn manifest_hash_hex(manifest: &VaultManifest) -> Result<String, VaultManifestError> {
    let json = serde_json::to_vec(manifest)?;
    let digest = Sha256::digest(json);
    Ok(hex_string(&digest))
}

/// Compare two manifest hashes in constant time.
///
/// Use this instead of `==` to avoid timing side-channels when verifying
/// manifest integrity. Both inputs should be 64-character lowercase hex strings
/// from [`manifest_hash_hex`].
pub fn manifest_hash_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_manifest_content() {
        let manifest = VaultManifest {
            object_kind: VaultManifestKind::Note,
            object_id: "note-1".to_string(),
            object_version: 1,
            manifest_hash: None,
            previous_manifest_hash: None,
            content_hash: "abc123".to_string(),
            key_version: 1,
            updated_at: "2026-03-27T00:00:00Z".to_string(),
            chunks: vec![VaultChunkDescriptor {
                chunk_id: "chunk-1".to_string(),
                plaintext_byte_size: 11,
                ciphertext_byte_size: 27,
                content_hash: "deadbeef".to_string(),
            }],
        };

        let hash = manifest_hash_hex(&manifest).expect("hash");
        assert_eq!(hash.len(), 64);
    }
}
