// Run once to create the compatibility fixtures:
//
//   cargo test generate_compat_fixtures -- --ignored --nocapture
//
// Then commit the generated JSON files into tests/fixtures/compat/.
// After that, the compat_fixtures test (not ignored) will verify every
// future build can still decrypt them.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use peachnote_vault_core::crypto::{
    build_namespaced_aad, derive_namespaced_key, encode_envelope, seal_namespaced, seal_with_key,
    VaultEnvelope, VAULT_ALGORITHM_XCHACHA20POLY1305,
};
use peachnote_vault_core::manifest::{
    manifest_hash_hex, VaultChunkDescriptor, VaultManifest, VaultManifestKind,
};
use peachnote_vault_core::recovery::{
    derive_recovery_wrap_key, encode_recovery_bundle_document, RecoveryBundleDocument,
    RecoveryBundleKdf, RECOVERY_AAD, RECOVERY_ARGON2_ITERATIONS, RECOVERY_ARGON2_MEMORY_KIB,
    RECOVERY_ARGON2_PARALLELISM, RECOVERY_BUNDLE_VERSION, RECOVERY_KDF_ALGORITHM,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

fn compat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat")
}

#[derive(Serialize, Deserialize)]
struct EnvelopeFixture {
    root_key_hex: String,
    namespace: String,
    scope: String,
    key_version: u32,
    extra_aad_hex: Option<String>,
    plaintext_utf8: String,
    envelope_json: String,
}

#[derive(Serialize, Deserialize)]
struct DerivationFixture {
    root_key_hex: String,
    namespace: String,
    scope: String,
    key_version: u32,
    derived_key_hex: String,
    aad_hex: String,
}

#[derive(Serialize, Deserialize)]
struct ManifestFixture {
    manifest_json: String,
    expected_hash: String,
}

#[derive(Serialize, Deserialize)]
struct RecoveryFixture {
    phrase: String,
    payload_json: String,
    bundle_pem: String,
}

#[derive(Serialize, Deserialize)]
struct RecoveryPayload {
    test_key: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore]
fn generate_envelope_fixture() {
    let root_key = [0x42u8; 32];
    let ns = "quickpeach.notes";
    let scope = "note/fixture-001";
    let pt = "This is a compatibility test note. If you can read this after decryption, v1 format is intact.";

    let env = seal_namespaced(&root_key, ns, scope, pt.as_bytes(), None, 1).unwrap();
    let encoded = encode_envelope(&env);
    let envelope_json = serde_json::to_string_pretty(&encoded).unwrap();

    let fixture = EnvelopeFixture {
        root_key_hex: hex(&root_key),
        namespace: ns.into(),
        scope: scope.into(),
        key_version: 1,
        extra_aad_hex: None,
        plaintext_utf8: pt.into(),
        envelope_json,
    };

    let path = compat_dir().join("envelope-v1.json");
    fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    println!("wrote {}", path.display());
}

#[test]
#[ignore]
fn generate_envelope_with_aad_fixture() {
    let root_key = [0x43u8; 32];
    let ns = "quickpeach.attachments";
    let scope = "attachment/photo.png";
    let extra_aad = b"image/png";
    let pt = b"fake-png-bytes-for-testing";

    let key = derive_namespaced_key(&root_key, ns, scope, 1).unwrap();
    let aad = build_namespaced_aad(ns, scope, 1, Some(extra_aad)).unwrap();
    let env = seal_with_key(&key, pt, &aad, 1).unwrap();
    let encoded = encode_envelope(&env);
    let envelope_json = serde_json::to_string_pretty(&encoded).unwrap();

    let fixture = EnvelopeFixture {
        root_key_hex: hex(&root_key),
        namespace: ns.into(),
        scope: scope.into(),
        key_version: 1,
        extra_aad_hex: Some(hex(extra_aad)),
        plaintext_utf8: String::from_utf8_lossy(pt).into(),
        envelope_json,
    };

    let path = compat_dir().join("envelope-with-aad-v1.json");
    fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    println!("wrote {}", path.display());
}

#[test]
#[ignore]
fn generate_derivation_fixture() {
    let cases = vec![
        ([0x0bu8; 32], "test-ns", "test-scope", 1u32),
        ([0x42u8; 32], "quickpeach.notes", "note/fixture-001", 1),
        (
            [0x43u8; 32],
            "quickpeach.attachments",
            "attachment/photo.png",
            1,
        ),
        ([0x44u8; 32], "quickpeach.extensions", "ext/demo-plugin", 1),
        ([0x0bu8; 32], "test-ns", "test-scope", 2), // version 2 for drift check
    ];

    let mut fixtures = Vec::new();
    for (root, ns, scope, ver) in cases {
        let dk = derive_namespaced_key(&root, ns, scope, ver).unwrap();
        let aad = build_namespaced_aad(ns, scope, ver, None).unwrap();
        fixtures.push(DerivationFixture {
            root_key_hex: hex(&root),
            namespace: ns.into(),
            scope: scope.into(),
            key_version: ver,
            derived_key_hex: hex(dk.as_ref()),
            aad_hex: hex(&aad),
        });
    }

    let path = compat_dir().join("derivations-v1.json");
    fs::write(&path, serde_json::to_string_pretty(&fixtures).unwrap()).unwrap();
    println!("wrote {} ({} entries)", path.display(), fixtures.len());
}

#[test]
#[ignore]
fn generate_manifest_fixture() {
    let manifest = VaultManifest {
        object_kind: VaultManifestKind::Note,
        object_id: "note-fixture-001".into(),
        object_version: 1,
        manifest_hash: None,
        previous_manifest_hash: None,
        content_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        key_version: 1,
        updated_at: "2026-03-31T00:00:00Z".into(),
        chunks: vec![VaultChunkDescriptor {
            chunk_id: "chunk-a".into(),
            plaintext_byte_size: 94,
            ciphertext_byte_size: 110,
            content_hash: "abcdef1234567890".into(),
        }],
    };

    let hash = manifest_hash_hex(&manifest).unwrap();
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();

    let fixture = ManifestFixture {
        manifest_json,
        expected_hash: hash,
    };

    let path = compat_dir().join("manifest-v1.json");
    fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    println!("wrote {}", path.display());
}

#[test]
#[ignore]
fn generate_recovery_fixture() {
    // Use fixed inputs so the checked-in fixture is reproducible and the
    // emitted PEM body always contains the current binary recovery format.
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let payload = RecoveryPayload {
        test_key: "ff".repeat(32),
    };
    let salt = *b"recovery-fixture";
    let nonce = *b"vault-core-fixture-nonce";
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let wrap_key = derive_recovery_wrap_key(
        phrase,
        &salt,
        RECOVERY_ARGON2_MEMORY_KIB,
        RECOVERY_ARGON2_ITERATIONS,
        RECOVERY_ARGON2_PARALLELISM,
    )
    .unwrap();
    let ciphertext = XChaCha20Poly1305::new((&*wrap_key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &payload_bytes,
                aad: RECOVERY_AAD,
            },
        )
        .unwrap();
    let envelope = VaultEnvelope {
        algorithm: VAULT_ALGORITHM_XCHACHA20POLY1305.into(),
        key_version: RECOVERY_BUNDLE_VERSION,
        nonce,
        ciphertext,
    };
    let document = RecoveryBundleDocument {
        format: "quickpeach-recovery-bundle".into(),
        version: RECOVERY_BUNDLE_VERSION,
        kdf: RecoveryBundleKdf {
            algorithm: RECOVERY_KDF_ALGORITHM.into(),
            salt_base64: BASE64_STANDARD.encode(salt),
            memory_kib: RECOVERY_ARGON2_MEMORY_KIB,
            iterations: RECOVERY_ARGON2_ITERATIONS,
            parallelism: RECOVERY_ARGON2_PARALLELISM,
        },
        envelope: encode_envelope(&envelope),
    };

    let bundle = encode_recovery_bundle_document(&document).unwrap();
    let payload_json = serde_json::to_string_pretty(&payload).unwrap();

    let fixture = RecoveryFixture {
        phrase: phrase.into(),
        payload_json,
        bundle_pem: bundle,
    };

    let path = compat_dir().join("recovery-bundle-v1.json");
    fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    println!("wrote {}", path.display());
}
