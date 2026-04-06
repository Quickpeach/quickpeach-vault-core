use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use peachnote_vault_core::crypto::{
    build_namespaced_aad, decode_envelope, derive_namespaced_key, open_namespaced, open_with_key,
    seal_namespaced, seal_with_key, VaultCryptoError, VaultEnvelope,
};
use std::collections::HashSet;

// -- known-answer: XChaCha20-Poly1305 from draft-irtf-cfrg-xchacha-03 A.3.1 --
//
// We validate two things here:
// 1. the upstream XChaCha20-Poly1305 implementation still matches the
//    published vector for these exact inputs
// 2. our envelope/opening plumbing can consume that exact vector
//
// Key   : 808182…9e9f (32 bytes)
// Nonce : 404142…5657 (24 bytes)
// AAD   : 50515253c0c1c2c3c4c5c6c7
// PT    : "Ladies and Gentlemen of the class of '99: …sunscreen would be it."
// CT||tag: bd6d17…c5bf21f966 + tag (last 16 bytes of combined output)

fn rfc_xchacha_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (index, byte) in k.iter_mut().enumerate() {
        *byte = 0x80 + index as u8;
    }
    k
}

fn rfc_xchacha_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    for (index, byte) in n.iter_mut().enumerate() {
        *byte = 0x40 + index as u8;
    }
    n
}

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input must have even length");
    input
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hi = (chunk[0] as char).to_digit(16).expect("valid hex") as u8;
            let lo = (chunk[1] as char).to_digit(16).expect("valid hex") as u8;
            (hi << 4) | lo
        })
        .collect()
}

#[test]
fn rfc_vector_exact_ciphertext_and_open() {
    let key = rfc_xchacha_key();
    let nonce = rfc_xchacha_nonce();
    let aad: &[u8] = &[
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_ciphertext = decode_hex(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52e",
        "c0875924c1c7987947deafd8780acf49"
    ));

    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad })
        .expect("encrypt with fixed nonce");
    assert_eq!(ciphertext, expected_ciphertext);

    let env = VaultEnvelope {
        algorithm: "xchacha20poly1305".into(),
        key_version: 1,
        nonce,
        ciphertext: expected_ciphertext,
    };

    let got = open_with_key(&key, &env, aad).unwrap();
    assert_eq!(got, pt);
}

// -- wrong key --

#[test]
fn wrong_root_key_namespaced() {
    let env = seal_namespaced(&[1u8; 32], "ns", "scope", b"secret", None, 1).unwrap();
    assert!(open_namespaced(&[2u8; 32], "ns", "scope", &env, None).is_err());
}

#[test]
fn wrong_raw_key() {
    let env = seal_with_key(&[0xAAu8; 32], b"hello", b"aad", 1).unwrap();
    assert!(open_with_key(&[0xBBu8; 32], &env, b"aad").is_err());
}

// -- tampered ciphertext (AEAD tag must catch it) --

#[test]
fn bit_flip_mid_ciphertext() {
    let key = [3u8; 32];
    let mut env = seal_with_key(&key, b"data", b"aad", 1).unwrap();
    let mid = env.ciphertext.len() / 2;
    env.ciphertext[mid] ^= 0x01;
    assert!(open_with_key(&key, &env, b"aad").is_err());
}

#[test]
fn truncated_tag() {
    let key = [4u8; 32];
    let mut env = seal_with_key(&key, b"hello world", b"aad", 1).unwrap();
    env.ciphertext.pop(); // chop one byte off the Poly1305 tag
    assert!(open_with_key(&key, &env, b"aad").is_err());
}

#[test]
fn appended_garbage() {
    let key = [5u8; 32];
    let mut env = seal_with_key(&key, b"payload", b"aad", 1).unwrap();
    env.ciphertext.push(0xFF);
    assert!(open_with_key(&key, &env, b"aad").is_err());
}

// -- tampered nonce --

#[test]
fn flipped_nonce() {
    let key = [6u8; 32];
    let mut env = seal_with_key(&key, b"data", b"aad", 1).unwrap();
    env.nonce[0] ^= 0xFF;
    assert!(open_with_key(&key, &env, b"aad").is_err());
}

// -- wrong AAD --

#[test]
fn wrong_aad() {
    let key = [7u8; 32];
    let env = seal_with_key(&key, b"data", b"correct", 1).unwrap();
    assert!(open_with_key(&key, &env, b"wrong").is_err());
}

#[test]
fn empty_vs_present_aad() {
    let key = [8u8; 32];
    let env = seal_with_key(&key, b"data", b"some-aad", 1).unwrap();
    assert!(open_with_key(&key, &env, b"").is_err());
}

// -- namespace / scope isolation --

#[test]
fn cross_namespace() {
    let key = [9u8; 32];
    let env = seal_namespaced(&key, "ns-a", "scope", b"x", None, 1).unwrap();
    assert!(open_namespaced(&key, "ns-b", "scope", &env, None).is_err());
}

#[test]
fn cross_scope() {
    let key = [10u8; 32];
    let env = seal_namespaced(&key, "ns", "scope-a", b"x", None, 1).unwrap();
    assert!(open_namespaced(&key, "ns", "scope-b", &env, None).is_err());
}

#[test]
fn cross_extra_aad() {
    let key = [11u8; 32];
    let env = seal_namespaced(&key, "ns", "scope", b"x", Some(b"aad-a"), 1).unwrap();
    assert!(open_namespaced(&key, "ns", "scope", &env, Some(b"aad-b")).is_err());
}

// -- key version mismatch --

#[test]
fn version_mismatch() {
    let key = [12u8; 32];
    let env = seal_namespaced(&key, "ns", "scope", b"data", None, 1).unwrap();

    // try to open with v2 derived key + v2 AAD
    let dk2 = derive_namespaced_key(&key, "ns", "scope", 2).unwrap();
    let aad2 = build_namespaced_aad("ns", "scope", 2, None).unwrap();
    assert!(open_with_key(&dk2, &env, &aad2).is_err());
}

// -- nonce uniqueness --

#[test]
fn unique_nonces_over_100_seals() {
    let key = [13u8; 32];
    let mut seen = HashSet::new();
    for _ in 0..100 {
        let env = seal_with_key(&key, b"same", b"aad", 1).unwrap();
        assert!(
            seen.insert(env.nonce),
            "nonce collision on 192-bit random nonce"
        );
    }
}

#[test]
fn same_plaintext_different_ciphertext() {
    let key = [14u8; 32];
    let e1 = seal_with_key(&key, b"same", b"aad", 1).unwrap();
    let e2 = seal_with_key(&key, b"same", b"aad", 1).unwrap();
    assert_ne!(e1.ciphertext, e2.ciphertext);
    assert_ne!(e1.nonce, e2.nonce);
}

// -- edge sizes --

#[test]
fn empty_plaintext() {
    let key = [15u8; 32];
    let env = seal_with_key(&key, b"", b"meta", 1).unwrap();
    assert_eq!(open_with_key(&key, &env, b"meta").unwrap(), b"");
}

#[test]
fn one_megabyte_plaintext() {
    let key = [16u8; 32];
    let pt: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let env = seal_with_key(&key, &pt, b"big", 1).unwrap();
    assert_eq!(open_with_key(&key, &env, b"big").unwrap(), pt);
}

// -- algorithm gate --

#[test]
fn rejects_unknown_algorithm() {
    let key = [17u8; 32];
    let mut env = seal_with_key(&key, b"x", b"aad", 1).unwrap();
    env.algorithm = "aes-256-gcm".into();
    assert!(matches!(
        open_with_key(&key, &env, b"aad"),
        Err(VaultCryptoError::UnsupportedAlgorithm(_))
    ));
}

// -- base64 envelope edge cases --

#[test]
fn bad_base64_nonce() {
    let enc = peachnote_vault_core::EncodedVaultEnvelope {
        algorithm: "xchacha20poly1305".into(),
        key_version: 1,
        nonce_base64: "not-valid!!!".into(),
        ciphertext_base64: "AAAA".into(),
    };
    assert!(decode_envelope(&enc).is_err());
}

#[test]
fn bad_base64_ciphertext() {
    let enc = peachnote_vault_core::EncodedVaultEnvelope {
        algorithm: "xchacha20poly1305".into(),
        key_version: 1,
        nonce_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        ciphertext_base64: "%%%".into(),
    };
    assert!(matches!(
        decode_envelope(&enc),
        Err(VaultCryptoError::InvalidBase64(_))
    ));
}

#[test]
fn short_nonce_16_bytes() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let enc = peachnote_vault_core::EncodedVaultEnvelope {
        algorithm: "xchacha20poly1305".into(),
        key_version: 1,
        nonce_base64: STANDARD.encode([0u8; 16]), // should be 24
        ciphertext_base64: STANDARD.encode([0u8; 32]),
    };
    assert!(matches!(
        decode_envelope(&enc),
        Err(VaultCryptoError::InvalidNonceLength)
    ));
}
