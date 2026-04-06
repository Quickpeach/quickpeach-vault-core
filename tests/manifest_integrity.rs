use peachnote_vault_core::manifest::{
    manifest_hash_hex, VaultChunkDescriptor, VaultManifest, VaultManifestKind,
};
use std::collections::HashSet;

fn make(version: u64) -> VaultManifest {
    VaultManifest {
        object_kind: VaultManifestKind::Note,
        object_id: "note-abc".into(),
        object_version: version,
        manifest_hash: None,
        previous_manifest_hash: None,
        content_hash: "deadbeef".into(),
        key_version: 1,
        updated_at: "2026-03-27T00:00:00Z".into(),
        chunks: vec![VaultChunkDescriptor {
            chunk_id: "chunk-1".into(),
            plaintext_byte_size: 100,
            ciphertext_byte_size: 116,
            content_hash: "abc123".into(),
        }],
    }
}

// -- determinism --

#[test]
fn identical_manifests_same_hash() {
    assert_eq!(
        manifest_hash_hex(&make(1)).unwrap(),
        manifest_hash_hex(&make(1)).unwrap()
    );
}

// -- valid hex output --

#[test]
fn hash_is_lowercase_hex_64_chars() {
    let h = manifest_hash_hex(&make(1)).unwrap();
    assert_eq!(h.len(), 64);
    assert!(h
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

// -- any single-field mutation changes the hash --

#[test]
fn version_changes_hash() {
    assert_ne!(
        manifest_hash_hex(&make(1)).unwrap(),
        manifest_hash_hex(&make(2)).unwrap()
    );
}

#[test]
fn content_hash_changes_hash() {
    let mut m = make(1);
    let h1 = manifest_hash_hex(&m).unwrap();
    m.content_hash = "cafebabe".into();
    assert_ne!(h1, manifest_hash_hex(&m).unwrap());
}

#[test]
fn object_id_changes_hash() {
    let mut m = make(1);
    let h1 = manifest_hash_hex(&m).unwrap();
    m.object_id = "note-xyz".into();
    assert_ne!(h1, manifest_hash_hex(&m).unwrap());
}

#[test]
fn timestamp_changes_hash() {
    let mut m = make(1);
    let h1 = manifest_hash_hex(&m).unwrap();
    m.updated_at = "2026-03-28T00:00:00Z".into();
    assert_ne!(h1, manifest_hash_hex(&m).unwrap());
}

#[test]
fn extra_chunk_changes_hash() {
    let mut m = make(1);
    let h1 = manifest_hash_hex(&m).unwrap();
    m.chunks.push(VaultChunkDescriptor {
        chunk_id: "chunk-2".into(),
        plaintext_byte_size: 50,
        ciphertext_byte_size: 66,
        content_hash: "def456".into(),
    });
    assert_ne!(h1, manifest_hash_hex(&m).unwrap());
}

#[test]
fn kind_changes_hash() {
    let mut m = make(1);
    let h1 = manifest_hash_hex(&m).unwrap();
    m.object_kind = VaultManifestKind::Attachment;
    assert_ne!(h1, manifest_hash_hex(&m).unwrap());
}

// -- hash chain: previous_manifest_hash links versions --

#[test]
fn hash_chain() {
    let v1 = make(1);
    let v1_hash = manifest_hash_hex(&v1).unwrap();

    let mut v2 = make(2);
    v2.previous_manifest_hash = Some(v1_hash.clone());
    let v2_hash = manifest_hash_hex(&v2).unwrap();

    // tamper the chain link
    let mut v2_bad = v2.clone();
    v2_bad.previous_manifest_hash = Some("0".repeat(64));
    assert_ne!(v2_hash, manifest_hash_hex(&v2_bad).unwrap());
}

// -- empty chunks --

#[test]
fn no_chunks_still_hashes() {
    let mut m = make(1);
    m.chunks.clear();
    assert_eq!(manifest_hash_hex(&m).unwrap().len(), 64);
}

// -- every VaultManifestKind variant produces a distinct hash --

#[test]
fn all_kinds_distinct() {
    let kinds = vec![
        VaultManifestKind::Note,
        VaultManifestKind::Attachment,
        VaultManifestKind::Palette,
        VaultManifestKind::ExtensionStorage,
        VaultManifestKind::ExtensionSyncState,
        VaultManifestKind::Other("custom".into()),
    ];
    let mut hashes = HashSet::new();
    for kind in kinds {
        let mut m = make(1);
        m.object_kind = kind;
        assert!(hashes.insert(manifest_hash_hex(&m).unwrap()));
    }
}
