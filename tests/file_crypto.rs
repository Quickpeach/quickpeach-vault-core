//! Round-trip tests against real files on disk.
//!
//! These use the fixture files in tests/fixtures/ to make sure we handle
//! actual file contents (not just synthetic byte slices) through the full
//! seal → encode → decode → open pipeline.

use peachnote_vault_core::crypto::{
    decode_envelope, encode_envelope, open_namespaced, seal_namespaced,
};
use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Seal a real file, put it through the base64 transport form, and verify
/// the decrypted output is byte-identical to the original.
fn assert_file_round_trips(filename: &str, scope: &str, root_key: &[u8; 32]) {
    let path = fixtures_dir().join(filename);
    let original = fs::read(&path).unwrap_or_else(|e| panic!("{filename}: {e}"));
    let aad = path.file_name().unwrap().as_encoded_bytes();

    let env = seal_namespaced(root_key, "vault.notes", scope, &original, Some(aad), 1)
        .expect("seal failed");

    // base64 transport round-trip
    let decoded = decode_envelope(&encode_envelope(&env)).expect("envelope codec failed");
    assert_eq!(decoded, env);

    let plaintext =
        open_namespaced(root_key, "vault.notes", scope, &decoded, Some(aad)).expect("open failed");
    assert_eq!(plaintext, original, "{filename}: decrypted content differs");
}

#[test]
fn txt_file_round_trip() {
    assert_file_round_trips("sample.txt", "files/txt", &[0xABu8; 32]);
}

#[test]
fn md_file_round_trip() {
    assert_file_round_trips("sample.md", "files/md", &[0xCDu8; 32]);
}
