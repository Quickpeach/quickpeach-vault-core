// Compatibility fixture tests.
//
// These read the JSON fixtures in tests/fixtures/compat/ (generated once
// by generate_compat_fixtures.rs) and verify the current code can still
// produce identical outputs for derivation/manifest and can still decrypt
// the envelope/recovery payloads.
//
// If any of these fail after a dependency upgrade, it means the v1 format
// has drifted. Do not release.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use peachnote_vault_core::crypto::{
    build_namespaced_aad, decode_envelope, derive_namespaced_key, open_namespaced, open_with_key,
};
use peachnote_vault_core::manifest::{manifest_hash_hex, VaultManifest};
use peachnote_vault_core::recovery::open_recovery_bundle;
use peachnote_vault_core::EncodedVaultEnvelope;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

fn compat_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat")
}

fn decode_hex(h: &str) -> Vec<u8> {
    h.as_bytes()
        .chunks(2)
        .map(|c| {
            let hi = (c[0] as char).to_digit(16).unwrap() as u8;
            let lo = (c[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}

fn hex_to_key(h: &str) -> [u8; 32] {
    let v = decode_hex(h);
    v.try_into().expect("key must be 32 bytes")
}

// -- envelope fixtures --

#[derive(Deserialize)]
struct EnvelopeFixture {
    root_key_hex: String,
    namespace: String,
    scope: String,
    key_version: u32,
    extra_aad_hex: Option<String>,
    plaintext_utf8: String,
    envelope_json: String,
}

fn try_envelope_fixture(name: &str) {
    let path = compat_dir().join(name);
    if !path.exists() {
        eprintln!("skip {name}: run generate_compat_fixtures first");
        return;
    }
    let fixture: EnvelopeFixture =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let root_key = hex_to_key(&fixture.root_key_hex);
    let encoded: EncodedVaultEnvelope = serde_json::from_str(&fixture.envelope_json).unwrap();
    let envelope = decode_envelope(&encoded).unwrap();

    let extra_aad = fixture.extra_aad_hex.as_ref().map(|h| decode_hex(h));
    let extra_ref = extra_aad.as_deref();

    // if extra AAD was used, we need to open with raw key + full AAD
    // (because the fixture was sealed with seal_with_key, not seal_namespaced)
    if extra_ref.is_some() {
        let dk = derive_namespaced_key(
            &root_key,
            &fixture.namespace,
            &fixture.scope,
            fixture.key_version,
        )
        .unwrap();
        let aad = build_namespaced_aad(
            &fixture.namespace,
            &fixture.scope,
            fixture.key_version,
            extra_ref,
        )
        .unwrap();
        let pt = open_with_key(&dk, &envelope, &aad).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&pt),
            fixture.plaintext_utf8,
            "decrypted plaintext mismatch in {name}"
        );
    } else {
        let pt = open_namespaced(
            &root_key,
            &fixture.namespace,
            &fixture.scope,
            &envelope,
            None,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&pt),
            fixture.plaintext_utf8,
            "decrypted plaintext mismatch in {name}"
        );
    }
}

#[test]
fn compat_envelope_v1() {
    try_envelope_fixture("envelope-v1.json");
}

#[test]
fn compat_envelope_with_aad_v1() {
    try_envelope_fixture("envelope-with-aad-v1.json");
}

// -- derivation fixtures --

#[derive(Deserialize)]
struct DerivationFixture {
    root_key_hex: String,
    namespace: String,
    scope: String,
    key_version: u32,
    derived_key_hex: String,
    aad_hex: String,
}

#[test]
fn compat_derivations_v1() {
    let path = compat_dir().join("derivations-v1.json");
    if !path.exists() {
        eprintln!("skip derivations: run generate_compat_fixtures first");
        return;
    }
    let fixtures: Vec<DerivationFixture> =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

    for (i, f) in fixtures.iter().enumerate() {
        let root = hex_to_key(&f.root_key_hex);
        let dk = derive_namespaced_key(&root, &f.namespace, &f.scope, f.key_version).unwrap();
        let dk_hex: String = dk.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            dk_hex, f.derived_key_hex,
            "derivation mismatch at index {i}"
        );

        let aad = build_namespaced_aad(&f.namespace, &f.scope, f.key_version, None).unwrap();
        let aad_hex: String = aad.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(aad_hex, f.aad_hex, "AAD mismatch at index {i}");
    }
}

// -- manifest fixtures --

#[derive(Deserialize)]
struct ManifestFixture {
    manifest_json: String,
    expected_hash: String,
}

#[test]
fn compat_manifest_v1() {
    let path = compat_dir().join("manifest-v1.json");
    if !path.exists() {
        eprintln!("skip manifest: run generate_compat_fixtures first");
        return;
    }
    let fixture: ManifestFixture =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let manifest: VaultManifest = serde_json::from_str(&fixture.manifest_json).unwrap();
    let hash = manifest_hash_hex(&manifest).unwrap();
    assert_eq!(hash, fixture.expected_hash, "manifest hash drifted");
}

// -- recovery fixtures --

#[derive(Deserialize)]
struct RecoveryFixture {
    phrase: String,
    payload_json: String,
    bundle_pem: String,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct RecoveryPayload {
    test_key: String,
}

#[test]
fn compat_recovery_v1() {
    let path = compat_dir().join("recovery-bundle-v1.json");
    if !path.exists() {
        eprintln!("skip recovery: run generate_compat_fixtures first");
        return;
    }
    let fixture: RecoveryFixture =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let pem_body = fixture
        .bundle_pem
        .trim()
        .strip_prefix("-----BEGIN QUICKPEACH RECOVERY BUNDLE-----")
        .unwrap()
        .trim()
        .strip_suffix("-----END QUICKPEACH RECOVERY BUNDLE-----")
        .unwrap()
        .trim()
        .replace('\n', "");
    let pem_bytes = BASE64_STANDARD.decode(pem_body).unwrap();
    assert_eq!(&pem_bytes[..4], b"QPRB", "fixture must store binary PEM");

    let expected: RecoveryPayload = serde_json::from_str(&fixture.payload_json).unwrap();
    let decoded =
        open_recovery_bundle::<RecoveryPayload>(&fixture.bundle_pem, &fixture.phrase).unwrap();
    assert_eq!(decoded.payload, expected, "recovery payload mismatch");
}
