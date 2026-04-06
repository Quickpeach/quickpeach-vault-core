//! Property-based tests for the vault crypto layer.
//!
//! Hand-picked test vectors prove specific cases; these prove structural
//! invariants hold for *all* inputs. proptest shrinks failures automatically.

use peachnote_vault_core::crypto::{
    decode_envelope, derive_namespaced_key, encode_envelope, open_namespaced, open_with_key,
    seal_namespaced, seal_with_key, VaultCryptoError, VAULT_ALGORITHM_XCHACHA20POLY1305,
};
use peachnote_vault_core::manifest::{manifest_hash_hex, VaultManifest, VaultManifestKind};
use proptest::prelude::*;

// ── strategies ──────────────────────────────────────────────────────

fn any_key() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

fn valid_namespace() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9._-]{0,30}"
}

fn valid_scope() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9._:/-]{0,60}"
}

fn valid_version() -> impl Strategy<Value = u32> {
    1..=100u32
}

fn sample_manifest(object_id: &str, content_hash: &str) -> VaultManifest {
    VaultManifest {
        object_kind: VaultManifestKind::Note,
        object_id: object_id.to_string(),
        object_version: 1,
        manifest_hash: None,
        previous_manifest_hash: None,
        content_hash: content_hash.to_string(),
        key_version: 1,
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        chunks: vec![],
    }
}

// ── AEAD core guarantees ────────────────────────────────────────────

proptest! {
    #[test]
    fn seal_then_open_is_identity(
        key in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        aad in prop::collection::vec(any::<u8>(), 0..256),
        ver in valid_version(),
    ) {
        let env = seal_with_key(&key, &plaintext, &aad, ver).unwrap();
        prop_assert_eq!(open_with_key(&key, &env, &aad).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_is_rejected(
        k1 in any_key(),
        k2 in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        aad in prop::collection::vec(any::<u8>(), 0..64),
        ver in valid_version(),
    ) {
        prop_assume!(k1 != k2);
        let env = seal_with_key(&k1, &plaintext, &aad, ver).unwrap();
        prop_assert!(open_with_key(&k2, &env, &aad).is_err());
    }

    #[test]
    fn wrong_aad_is_rejected(
        key in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        aad_a in prop::collection::vec(any::<u8>(), 0..64),
        aad_b in prop::collection::vec(any::<u8>(), 0..64),
        ver in valid_version(),
    ) {
        prop_assume!(aad_a != aad_b);
        let env = seal_with_key(&key, &plaintext, &aad_a, ver).unwrap();
        prop_assert!(open_with_key(&key, &env, &aad_b).is_err());
    }

    /// Poly1305 tag is 16 bytes, so ciphertext = plaintext + 16.
    #[test]
    fn ciphertext_overhead_is_16(
        key in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        ver in valid_version(),
    ) {
        let env = seal_with_key(&key, &plaintext, &[], ver).unwrap();
        prop_assert_eq!(env.ciphertext.len(), plaintext.len() + 16);
    }

    /// Random 24-byte nonce → duplicate probability is ~2^-192 per pair.
    #[test]
    fn each_seal_uses_a_fresh_nonce(
        key in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        ver in valid_version(),
    ) {
        let a = seal_with_key(&key, &plaintext, &[], ver).unwrap();
        let b = seal_with_key(&key, &plaintext, &[], ver).unwrap();
        prop_assert_ne!(a.nonce, b.nonce);
        prop_assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn any_bit_flip_is_detected(
        key in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        ver in valid_version(),
        bit_pos in any::<prop::sample::Index>(),
    ) {
        let mut env = seal_with_key(&key, &plaintext, &[], ver).unwrap();
        let idx = bit_pos.index(env.ciphertext.len());
        env.ciphertext[idx] ^= 1;
        prop_assert!(open_with_key(&key, &env, &[]).is_err());
    }
}

// ── envelope base64 encoding ────────────────────────────────────────

proptest! {
    #[test]
    fn encode_then_decode_is_identity(
        key in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        ver in valid_version(),
    ) {
        let env = seal_with_key(&key, &plaintext, &[], ver).unwrap();
        let decoded = decode_envelope(&encode_envelope(&env)).unwrap();
        prop_assert_eq!(decoded, env);
    }

    #[test]
    fn algorithm_is_always_xchacha20(
        key in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 0..128),
        ver in valid_version(),
    ) {
        let env = seal_with_key(&key, &plaintext, &[], ver).unwrap();
        prop_assert_eq!(env.algorithm, VAULT_ALGORITHM_XCHACHA20POLY1305);
    }

    #[test]
    fn nonce_length_is_24(
        key in any_key(),
        plaintext in prop::collection::vec(any::<u8>(), 0..128),
        ver in valid_version(),
    ) {
        let env = seal_with_key(&key, &plaintext, &[], ver).unwrap();
        prop_assert_eq!(env.nonce.len(), 24);
    }
}

// ── namespaced key derivation ───────────────────────────────────────

proptest! {
    #[test]
    fn derivation_is_deterministic(
        root in any_key(),
        ns in valid_namespace(),
        scope in valid_scope(),
        ver in valid_version(),
    ) {
        let a = derive_namespaced_key(&root, &ns, &scope, ver).unwrap();
        let b = derive_namespaced_key(&root, &ns, &scope, ver).unwrap();
        prop_assert_eq!(*a, *b);
    }

    #[test]
    fn distinct_roots_yield_distinct_keys(
        r1 in any_key(),
        r2 in any_key(),
        ns in valid_namespace(),
        scope in valid_scope(),
        ver in valid_version(),
    ) {
        prop_assume!(r1 != r2);
        let a = derive_namespaced_key(&r1, &ns, &scope, ver).unwrap();
        let b = derive_namespaced_key(&r2, &ns, &scope, ver).unwrap();
        prop_assert_ne!(*a, *b);
    }

    /// Full namespaced pipeline: derive → seal → open.
    #[test]
    fn namespaced_seal_open_round_trip(
        root in any_key(),
        ns in valid_namespace(),
        scope in valid_scope(),
        plaintext in prop::collection::vec(any::<u8>(), 0..2048),
        extra in proptest::option::of(prop::collection::vec(any::<u8>(), 0..64)),
        ver in valid_version(),
    ) {
        let extra_ref = extra.as_deref();
        let env = seal_namespaced(&root, &ns, &scope, &plaintext, extra_ref, ver).unwrap();
        prop_assert_eq!(
            open_namespaced(&root, &ns, &scope, &env, extra_ref).unwrap(),
            plaintext
        );
    }

    /// Envelope sealed under namespace A must not open under namespace B.
    #[test]
    fn namespaces_are_isolated(
        root in any_key(),
        ns_a in valid_namespace(),
        ns_b in valid_namespace(),
        scope in valid_scope(),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        ver in valid_version(),
    ) {
        prop_assume!(ns_a != ns_b);
        let env = seal_namespaced(&root, &ns_a, &scope, &plaintext, None, ver).unwrap();
        prop_assert!(open_namespaced(&root, &ns_b, &scope, &env, None).is_err());
    }

    #[test]
    fn version_zero_is_always_rejected(
        root in any_key(),
        ns in valid_namespace(),
        scope in valid_scope(),
    ) {
        prop_assert!(matches!(
            derive_namespaced_key(&root, &ns, &scope, 0),
            Err(VaultCryptoError::InvalidKeyVersion)
        ));
    }
}

// ── manifest hashing ────────────────────────────────────────────────

proptest! {
    #[test]
    fn manifest_hash_is_64_hex_chars(id in "[a-z]{1,10}", ver in 1..100u64) {
        let mut m = sample_manifest(&id, "aabbccdd");
        m.object_version = ver;
        let hash = manifest_hash_hex(&m).unwrap();
        prop_assert_eq!(hash.len(), 64);
        prop_assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_content_hashes_differ(a in "[a-f0-9]{8}", b in "[a-f0-9]{8}") {
        prop_assume!(a != b);
        prop_assert_ne!(
            manifest_hash_hex(&sample_manifest("note-1", &a)).unwrap(),
            manifest_hash_hex(&sample_manifest("note-1", &b)).unwrap()
        );
    }
}
