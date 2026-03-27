use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
pub enum VaultManifestError {
    #[error("manifest serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub fn manifest_hash_hex(manifest: &VaultManifest) -> Result<String, VaultManifestError> {
    let json = serde_json::to_vec(manifest)?;
    let digest = Sha256::digest(json);
    Ok(hex_string(&digest))
}

fn hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
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
