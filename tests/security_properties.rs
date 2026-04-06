//! Tests that document and verify the security boundaries of the vault format.
//!
//! Some of these assert properties we *rely on*; others exist to show we're
//! aware of a limitation (e.g., non-key-committing AEAD) and have mitigated
//! it rather than ignored it.

use peachnote_vault_core::crypto::{
    build_namespaced_aad, derive_namespaced_key, open_with_key, seal_with_key,
};

// ── key commitment ──────────────────────────────────────────────────
//
// XChaCha20-Poly1305 is *not* key-committing: an attacker can craft a
// ciphertext valid under two different keys. Our namespace-bound AAD
// mitigates this in practice because the attacker must also collide the
// (namespace, scope, version, extra) tuple.
//
// If multi-party sync requires key commitment later, the fix is to add
// BLAKE2b(key) into the AAD, or switch to a committing AEAD.

/// Same root key, same scope, same plaintext — but different namespaces
/// derive different keys and produce incompatible AAD, so cross-opening fails.
#[test]
fn cross_namespace_aad_prevents_confused_deputy() {
    let root = [0x55u8; 32];
    let pt = b"sensitive note content";

    let notes =
        peachnote_vault_core::seal_namespaced(&root, "app.notes", "note/1", pt, None, 1).unwrap();
    let attach =
        peachnote_vault_core::seal_namespaced(&root, "app.attachments", "note/1", pt, None, 1)
            .unwrap();

    // cannot swap
    assert!(peachnote_vault_core::open_namespaced(
        &root,
        "app.attachments",
        "note/1",
        &notes,
        None
    )
    .is_err());
    assert!(
        peachnote_vault_core::open_namespaced(&root, "app.notes", "note/1", &attach, None).is_err()
    );
}

// ── nonce quality ───────────────────────────────────────────────────
//
// With 24-byte random nonces the birthday bound is ~2^96. We just need
// to verify we aren't accidentally using zeroes or a counter.

#[test]
fn nonces_are_random() {
    let key = [0x11u8; 32];
    let nonces: Vec<_> = (0..50)
        .map(|_| seal_with_key(&key, b"x", &[], 1).unwrap().nonce)
        .collect();

    let unique: std::collections::HashSet<_> = nonces.iter().copied().collect();
    assert_eq!(unique.len(), nonces.len(), "no duplicates in 50 nonces");

    let first_bytes: std::collections::HashSet<_> = nonces.iter().map(|n| n[0]).collect();
    assert!(
        first_bytes.len() > 1,
        "first byte should vary (not a counter)"
    );

    assert!(nonces.iter().all(|n| *n != [0u8; 24]), "no all-zero nonce");
}

// ── domain separation ───────────────────────────────────────────────
//
// Namespace goes into the HKDF salt, scope into info. Even if the
// concatenated info strings look similar, the salt difference makes
// the derived keys unrelated.

#[test]
fn domain_boundary_cannot_be_confused() {
    let root = [0x33u8; 32];

    // "a.b" / "c" vs "a" / "b.c" — looks alike when concatenated, but salt differs
    assert_ne!(
        *derive_namespaced_key(&root, "a.b", "c", 1).unwrap(),
        *derive_namespaced_key(&root, "a", "b.c", 1).unwrap(),
    );
    assert_ne!(
        build_namespaced_aad("a.b", "c", 1, None).unwrap(),
        build_namespaced_aad("a", "b.c", 1, None).unwrap(),
    );

    // null-byte separators also prevent extra-AAD injection
    assert_ne!(
        build_namespaced_aad("ns", "scope", 1, Some(b"extra")).unwrap(),
        build_namespaced_aad("ns", "scope", 1, Some(b"extrb")).unwrap(),
    );
}

// ── ciphertext expansion ────────────────────────────────────────────

/// Poly1305 tag is exactly 16 bytes for every plaintext size.
/// If this changes, the binary wire format is broken.
#[test]
fn tag_overhead_is_constant_16() {
    let key = [0xFFu8; 32];
    for size in [0, 1, 15, 16, 17, 255, 1024, 65535] {
        let env = seal_with_key(&key, &vec![0xAA; size], &[], 1).unwrap();
        assert_eq!(env.ciphertext.len(), size + 16, "size={size}");
    }
}

// ── version rotation ────────────────────────────────────────────────
//
// Bumping the version changes both the derived key *and* the AAD,
// so old envelopes can't be opened with a new version.

#[test]
fn version_bump_invalidates_prior_envelopes() {
    let root = [0xEEu8; 32];
    let ns = "vault.notes";
    let scope = "note/rotation-test";

    let env_v1 =
        peachnote_vault_core::seal_namespaced(&root, ns, scope, b"v1 data", None, 1).unwrap();

    // v1 key opens v1 envelope
    assert!(peachnote_vault_core::open_namespaced(&root, ns, scope, &env_v1, None).is_ok());

    // v2 key cannot open v1 envelope
    let dk_v2 = derive_namespaced_key(&root, ns, scope, 2).unwrap();
    let aad_v2 = build_namespaced_aad(ns, scope, 2, None).unwrap();
    assert!(open_with_key(&dk_v2, &env_v1, &aad_v2).is_err());
}
