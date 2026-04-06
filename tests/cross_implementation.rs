//! Cross-implementation validation against the raw chacha20poly1305 crate.
//!
//! These tests encrypt on one side (raw crate or vault API) and decrypt on
//! the other, proving the envelope wire format matches what any conforming
//! XChaCha20-Poly1305 implementation would produce.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use peachnote_vault_core::crypto::{
    build_namespaced_aad, derive_namespaced_key, open_with_key, seal_with_key, VaultEnvelope,
    VAULT_ALGORITHM_XCHACHA20POLY1305,
};

/// Helper: encrypt raw bytes using the chacha20poly1305 crate directly.
fn raw_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("raw encrypt")
}

/// Helper: decrypt raw bytes using the chacha20poly1305 crate directly.
fn raw_decrypt(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .expect("raw decrypt")
}

#[test]
fn raw_encrypt_then_vault_open() {
    let root = [0xABu8; 32];
    let dk = derive_namespaced_key(&root, "interop.test", "cross/check", 1).unwrap();
    let aad = build_namespaced_aad("interop.test", "cross/check", 1, None).unwrap();

    let nonce = [0x42u8; 24];
    let plaintext = b"cross-implementation proof";
    let ciphertext = raw_encrypt(&dk, &nonce, plaintext, &aad);

    let env = VaultEnvelope {
        algorithm: VAULT_ALGORITHM_XCHACHA20POLY1305.to_string(),
        key_version: 1,
        nonce,
        ciphertext,
    };
    assert_eq!(open_with_key(&dk, &env, &aad).unwrap(), plaintext);
}

#[test]
fn vault_seal_then_raw_open() {
    let root = [0xCDu8; 32];
    let dk = derive_namespaced_key(&root, "interop.test", "cross/check", 1).unwrap();
    let aad = build_namespaced_aad("interop.test", "cross/check", 1, Some(b"extra")).unwrap();

    let plaintext = b"vault sealed, raw opened";
    let env = seal_with_key(&dk, plaintext, &aad, 1).unwrap();
    assert_eq!(
        raw_decrypt(&dk, &env.nonce, &env.ciphertext, &aad),
        plaintext
    );
}

/// End-to-end: derive → seal → verify metadata → raw open → vault open.
/// Covers key derivation, AAD construction, and AEAD in one shot.
#[test]
fn full_pipeline_matches_raw_crate() {
    let root = [0x77u8; 32];
    let ns = "notes.app";
    let scope = "note/abc-123";
    let ver = 3u32;
    let extra = b"filename:hello.md";

    let dk = derive_namespaced_key(&root, ns, scope, ver).unwrap();
    let aad = build_namespaced_aad(ns, scope, ver, Some(extra)).unwrap();

    let plaintext = b"# Hello\n\nThis is a note with some content.\n";
    let env = seal_with_key(&dk, plaintext, &aad, ver).unwrap();

    // sanity-check envelope shape
    assert_eq!(env.algorithm, VAULT_ALGORITHM_XCHACHA20POLY1305);
    assert_eq!(env.key_version, ver);
    assert_eq!(env.ciphertext.len(), plaintext.len() + 16);

    // raw crate agrees
    let from_raw = raw_decrypt(&dk, &env.nonce, &env.ciphertext, &aad);
    assert_eq!(from_raw, plaintext);

    // vault API agrees
    let from_vault = open_with_key(&dk, &env, &aad).unwrap();
    assert_eq!(from_vault, plaintext);
}
