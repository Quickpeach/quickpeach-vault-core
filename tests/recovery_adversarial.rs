//! Adversarial and edge-case tests for the recovery bundle system.
//!
//! Covers BIP-39 phrase handling, PEM structure, binary wire format,
//! legacy JSON compat, checkpoint verification, and tamper detection.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use peachnote_vault_core::recovery::{
    build_recovery_bundle, encode_recovery_bundle_document, generate_recovery_phrase,
    normalize_recovery_phrase, open_recovery_bundle, parse_recovery_bundle_document,
    recovery_phrase_words, verify_recovery_phrase_checkpoints, DecodedRecoveryBundle,
    RecoveryError, RecoveryPhraseCheckpoint, RECOVERY_BUNDLE_FOOTER, RECOVERY_BUNDLE_HEADER,
    RECOVERY_PHRASE_WORD_COUNT,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Payload {
    key: String,
}

fn test_payload(key: &str) -> Payload {
    Payload { key: key.into() }
}

/// Build a bundle from a fresh phrase and return both.
fn fresh_bundle(payload: &Payload) -> (String, String) {
    let phrase = generate_recovery_phrase().unwrap();
    let bundle = build_recovery_bundle(payload, &phrase).unwrap();
    (phrase, bundle)
}

/// Extract the raw binary bytes from inside PEM armor.
fn pem_body(bundle: &str) -> Vec<u8> {
    let b64 = bundle
        .trim()
        .strip_prefix(RECOVERY_BUNDLE_HEADER)
        .unwrap()
        .trim()
        .strip_suffix(RECOVERY_BUNDLE_FOOTER)
        .unwrap()
        .replace('\n', "");
    BASE64_STANDARD.decode(b64).unwrap()
}

/// Re-wrap raw bytes in PEM armor (single base64 line, no wrapping).
fn wrap_pem(bytes: &[u8]) -> String {
    format!(
        "{}\n{}\n{}",
        RECOVERY_BUNDLE_HEADER,
        BASE64_STANDARD.encode(bytes),
        RECOVERY_BUNDLE_FOOTER
    )
}

// ── BIP-39 phrase basics ────────────────────────────────────────────

const BIP39_ZERO: &str = concat!(
    "abandon abandon abandon abandon abandon abandon ",
    "abandon abandon abandon abandon abandon abandon ",
    "abandon abandon abandon abandon abandon abandon ",
    "abandon abandon abandon abandon abandon art"
);

#[test]
fn zero_entropy_phrase_normalises() {
    assert_eq!(normalize_recovery_phrase(BIP39_ZERO).unwrap(), BIP39_ZERO);
}

#[test]
fn zero_entropy_phrase_is_24_words() {
    let w = recovery_phrase_words(BIP39_ZERO).unwrap();
    assert_eq!(
        (w.len(), w[0].as_str(), w[23].as_str()),
        (24, "abandon", "art")
    );
}

#[test]
fn wrong_phrase_cannot_open() {
    let (_, bundle) = fresh_bundle(&test_payload("secret"));
    let other = generate_recovery_phrase().unwrap();
    assert!(open_recovery_bundle::<Payload>(&bundle, &other).is_err());
}

// ── PEM + binary wire format ────────────────────────────────────────

#[test]
fn bundle_pem_contains_qprb_binary() {
    let (_, bundle) = fresh_bundle(&test_payload("x"));
    assert!(bundle.starts_with(RECOVERY_BUNDLE_HEADER));
    assert!(bundle.trim().ends_with(RECOVERY_BUNDLE_FOOTER));

    let bytes = pem_body(&bundle);
    assert_eq!(&bytes[..4], b"QPRB");
    assert_eq!(bytes[4], 0x01);
}

#[test]
fn missing_pem_footer() {
    let (_, bundle) = fresh_bundle(&test_payload("x"));
    let broken = bundle.replace(RECOVERY_BUNDLE_FOOTER, "");
    assert!(parse_recovery_bundle_document(&broken).is_err());
}

#[test]
fn garbage_base64_inside_pem() {
    let bad = format!("{RECOVERY_BUNDLE_HEADER}\n!!!not-base64!!!\n{RECOVERY_BUNDLE_FOOTER}");
    assert!(parse_recovery_bundle_document(&bad).is_err());
}

#[test]
fn empty_input() {
    assert!(parse_recovery_bundle_document("").is_err());
}

// ── binary header field gates ───────────────────────────────────────

#[test]
fn corrupt_magic_rejected() {
    let (_, bundle) = fresh_bundle(&test_payload("x"));
    let mut raw = pem_body(&bundle);
    raw[0] = b'X';
    assert!(matches!(
        parse_recovery_bundle_document(&wrap_pem(&raw)),
        Err(RecoveryError::UnsupportedFormat) | Err(RecoveryError::InvalidJson(_))
    ));
}

#[test]
fn unknown_version_byte_rejected() {
    let (_, bundle) = fresh_bundle(&test_payload("x"));
    let mut raw = pem_body(&bundle);
    raw[4] = 0xFF;
    assert!(matches!(
        parse_recovery_bundle_document(&wrap_pem(&raw)),
        Err(RecoveryError::UnsupportedVersion)
    ));
}

#[test]
fn unknown_kdf_id_rejected() {
    let (_, bundle) = fresh_bundle(&test_payload("x"));
    let mut raw = pem_body(&bundle);
    raw[5] = 0xFF;
    assert!(matches!(
        parse_recovery_bundle_document(&wrap_pem(&raw)),
        Err(RecoveryError::UnsupportedKdf)
    ));
}

#[test]
fn legacy_json_version_gate() {
    let (_, bundle) = fresh_bundle(&test_payload("x"));
    let mut doc = parse_recovery_bundle_document(&bundle).unwrap();
    doc.version += 1;
    let bad = serde_json::to_string(&doc).unwrap();
    assert!(matches!(
        parse_recovery_bundle_document(&bad),
        Err(RecoveryError::UnsupportedVersion)
    ));
}

// ── legacy JSON compat ──────────────────────────────────────────────

#[test]
fn raw_json_still_accepted() {
    let (_, bundle) = fresh_bundle(&test_payload("legacy"));
    let doc = parse_recovery_bundle_document(&bundle).unwrap();
    let json = serde_json::to_string_pretty(&doc).unwrap();

    let re = parse_recovery_bundle_document(&json).unwrap();
    assert_eq!(re.version, doc.version);
    assert_eq!(re.kdf.memory_kib, doc.kdf.memory_kib);
}

#[test]
fn json_inside_pem_still_accepted() {
    let (_, bundle) = fresh_bundle(&test_payload("legacy"));
    let doc = parse_recovery_bundle_document(&bundle).unwrap();
    let legacy = format!(
        "{}\n{}\n{}",
        RECOVERY_BUNDLE_HEADER,
        serde_json::to_string_pretty(&doc).unwrap(),
        RECOVERY_BUNDLE_FOOTER
    );
    let re = parse_recovery_bundle_document(&legacy).unwrap();
    assert_eq!(re.version, doc.version);
}

// ── phrase normalisation ────────────────────────────────────────────

#[test]
fn extra_whitespace_normalises() {
    let phrase = generate_recovery_phrase().unwrap();
    let messy = format!("  {}  ", phrase.replace(' ', "   "));
    assert_eq!(normalize_recovery_phrase(&messy).unwrap(), phrase);
}

#[test]
fn invalid_bip39_word() {
    assert!(normalize_recovery_phrase("zzzzz ".repeat(24).trim()).is_err());
}

#[test]
fn twelve_word_phrase_rejected() {
    // valid BIP-39 mnemonic but we mandate 24 words (256-bit entropy)
    let result = normalize_recovery_phrase(concat!(
        "abandon abandon abandon abandon abandon abandon ",
        "abandon abandon abandon abandon abandon about"
    ));
    assert!(matches!(result, Err(RecoveryError::InvalidPhraseLength)));
}

#[test]
fn generated_phrase_is_always_24_words() {
    for _ in 0..5 {
        let w = recovery_phrase_words(&generate_recovery_phrase().unwrap()).unwrap();
        assert_eq!(w.len(), RECOVERY_PHRASE_WORD_COUNT);
    }
}

// ── checkpoint verification ─────────────────────────────────────────

#[test]
fn correct_checkpoints_pass() {
    let phrase = generate_recovery_phrase().unwrap();
    let words = recovery_phrase_words(&phrase).unwrap();
    verify_recovery_phrase_checkpoints(
        &phrase,
        &[
            RecoveryPhraseCheckpoint {
                index: 0,
                word: words[0].clone(),
            },
            RecoveryPhraseCheckpoint {
                index: 12,
                word: words[12].clone(),
            },
            RecoveryPhraseCheckpoint {
                index: 23,
                word: words[23].clone(),
            },
        ],
    )
    .unwrap();
}

#[test]
fn wrong_checkpoint_word() {
    let phrase = generate_recovery_phrase().unwrap();
    assert!(verify_recovery_phrase_checkpoints(
        &phrase,
        &[RecoveryPhraseCheckpoint {
            index: 0,
            word: "zzz".into()
        }],
    )
    .is_err());
}

#[test]
fn out_of_bounds_checkpoint() {
    let phrase = generate_recovery_phrase().unwrap();
    assert!(matches!(
        verify_recovery_phrase_checkpoints(
            &phrase,
            &[RecoveryPhraseCheckpoint {
                index: 99,
                word: "abandon".into()
            }],
        ),
        Err(RecoveryError::VerificationFailed)
    ));
}

#[test]
fn checkpoints_are_case_insensitive() {
    verify_recovery_phrase_checkpoints(
        BIP39_ZERO,
        &[RecoveryPhraseCheckpoint {
            index: 0,
            word: "ABANDON".into(),
        }],
    )
    .unwrap();
}

// ── full round-trip (slow: Argon2id ~2-5 s) ────────────────────────

#[test]
fn full_round_trip() {
    let payload = test_payload(&"ff".repeat(32));
    let (phrase, bundle) = fresh_bundle(&payload);

    // structural checks
    assert!(bundle.starts_with(RECOVERY_BUNDLE_HEADER));
    assert_eq!(&pem_body(&bundle)[..4], b"QPRB");

    let decoded: DecodedRecoveryBundle<Payload> = open_recovery_bundle(&bundle, &phrase).unwrap();
    assert_eq!(decoded.payload, payload);
}

// ── tampered ciphertext ─────────────────────────────────────────────

#[test]
fn flipped_ciphertext_bit_detected() {
    let (phrase, bundle) = fresh_bundle(&test_payload(&"ab".repeat(32)));
    let mut doc = parse_recovery_bundle_document(&bundle).unwrap();

    let mut ct = BASE64_STANDARD
        .decode(doc.envelope.ciphertext_base64.as_bytes())
        .unwrap();
    let mid = ct.len() / 2;
    ct[mid] ^= 0x01;
    doc.envelope.ciphertext_base64 = BASE64_STANDARD.encode(&ct);

    let tampered = encode_recovery_bundle_document(&doc).unwrap();
    assert!(open_recovery_bundle::<Payload>(&tampered, &phrase).is_err());
}

#[test]
fn invalid_base64_rejected_at_encode_time() {
    let (_, bundle) = fresh_bundle(&test_payload(&"ab".repeat(32)));
    let mut doc = parse_recovery_bundle_document(&bundle).unwrap();
    doc.envelope.ciphertext_base64 = "%%%".into();

    assert!(matches!(
        encode_recovery_bundle_document(&doc),
        Err(RecoveryError::InvalidEnvelope(_))
    ));
}
