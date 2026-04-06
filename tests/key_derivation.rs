use peachnote_vault_core::crypto::{build_namespaced_aad, derive_namespaced_key, VaultCryptoError};

// -- RFC 5869 appendix A, test case 1 (SHA-256) --
//
// We can't call HKDF directly through vault-core's public API (it's
// wrapped behind derive_namespaced_key which injects its own info
// string). So instead we pin a known-answer from our own wrapper:
// freeze the output of derive_namespaced_key with fixed inputs, then
// assert it never changes across crate upgrades.

#[test]
fn pinned_derivation_does_not_drift() {
    let root = [0x0bu8; 32];
    let k = derive_namespaced_key(&root, "test-ns", "test-scope", 1).unwrap();
    // If this changes, either the HKDF crate changed behaviour or we
    // changed the wrapper's info-string / normalization format. Treat
    // that as a compatibility break for vault-core v1.
    let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "a2b3d713176bada018eead333a144c586f69bc493fa7d496bef4738814100f67"
    );
    // Determinism: calling again with same inputs must match.
    let k2 = derive_namespaced_key(&root, "test-ns", "test-scope", 1).unwrap();
    assert_eq!(k, k2);
}

// -- determinism --

#[test]
fn same_inputs_same_output() {
    let root = [1u8; 32];
    let a = derive_namespaced_key(&root, "ns", "scope", 1).unwrap();
    let b = derive_namespaced_key(&root, "ns", "scope", 1).unwrap();
    assert_eq!(a, b);
}

// -- domain isolation --

#[test]
fn different_root() {
    let a = derive_namespaced_key(&[1u8; 32], "ns", "scope", 1).unwrap();
    let b = derive_namespaced_key(&[2u8; 32], "ns", "scope", 1).unwrap();
    assert_ne!(a, b);
}

#[test]
fn different_namespace() {
    let root = [3u8; 32];
    let a = derive_namespaced_key(&root, "notes", "scope", 1).unwrap();
    let b = derive_namespaced_key(&root, "attachments", "scope", 1).unwrap();
    assert_ne!(a, b);
}

#[test]
fn different_scope() {
    let root = [4u8; 32];
    let a = derive_namespaced_key(&root, "ns", "note/abc", 1).unwrap();
    let b = derive_namespaced_key(&root, "ns", "note/def", 1).unwrap();
    assert_ne!(a, b);
}

#[test]
fn different_version() {
    let root = [5u8; 32];
    let a = derive_namespaced_key(&root, "ns", "scope", 1).unwrap();
    let b = derive_namespaced_key(&root, "ns", "scope", 2).unwrap();
    assert_ne!(a, b);
}

// -- no namespace/scope path confusion --
// "quickpeach.notes" + "note/1"  !=  "quickpeach.note" + "s/note/1"
// even though the concatenation looks similar.

#[test]
fn namespace_scope_boundary_not_confused() {
    let root = [6u8; 32];
    let a = derive_namespaced_key(&root, "quickpeach.notes", "note/1", 1).unwrap();
    let b = derive_namespaced_key(&root, "quickpeach.note", "s/note/1", 1).unwrap();
    assert_ne!(a, b);
}

// -- scope validation --

#[test]
fn empty_scope() {
    assert!(matches!(
        derive_namespaced_key(&[0u8; 32], "ns", "", 1),
        Err(VaultCryptoError::EmptyScope)
    ));
}

#[test]
fn whitespace_scope() {
    assert!(matches!(
        derive_namespaced_key(&[0u8; 32], "ns", "   ", 1),
        Err(VaultCryptoError::EmptyScope)
    ));
}

#[test]
fn scope_129_chars() {
    let long = "a".repeat(129);
    assert!(matches!(
        derive_namespaced_key(&[0u8; 32], "ns", &long, 1),
        Err(VaultCryptoError::ScopeTooLong)
    ));
}

#[test]
fn scope_128_chars_ok() {
    assert!(derive_namespaced_key(&[0u8; 32], "ns", &"a".repeat(128), 1).is_ok());
}

#[test]
fn scope_rejects_bad_chars() {
    for bad in ["hello world", "note#1", "path\\back", "名前", "a{b}"] {
        assert!(
            matches!(
                derive_namespaced_key(&[0u8; 32], "ns", bad, 1),
                Err(VaultCryptoError::InvalidScope)
            ),
            "'{bad}' should be rejected"
        );
    }
}

#[test]
fn scope_accepts_allowed_chars() {
    for ok in ["note/abc-123", "storage:blob", "ext_data.v1", "a/b/c/d"] {
        assert!(
            derive_namespaced_key(&[0u8; 32], "ns", ok, 1).is_ok(),
            "'{ok}' should be accepted"
        );
    }
}

// -- namespace validation --

#[test]
fn empty_namespace() {
    assert!(matches!(
        derive_namespaced_key(&[0u8; 32], "", "scope", 1),
        Err(VaultCryptoError::EmptyNamespace)
    ));
}

#[test]
fn whitespace_namespace() {
    assert!(matches!(
        derive_namespaced_key(&[0u8; 32], "  \t  ", "scope", 1),
        Err(VaultCryptoError::EmptyNamespace)
    ));
}

// -- trimming normalises --

#[test]
fn trimmed_namespace_matches() {
    let root = [7u8; 32];
    let a = derive_namespaced_key(&root, "ns", "scope", 1).unwrap();
    let b = derive_namespaced_key(&root, "  ns  ", "scope", 1).unwrap();
    assert_eq!(a, b);
}

#[test]
fn trimmed_scope_matches() {
    let root = [8u8; 32];
    let a = derive_namespaced_key(&root, "ns", "scope", 1).unwrap();
    let b = derive_namespaced_key(&root, "ns", "  scope  ", 1).unwrap();
    assert_eq!(a, b);
}

// -- AAD construction --

#[test]
fn aad_format() {
    let aad = build_namespaced_aad("ns", "scope", 1, None).unwrap();
    assert_eq!(aad, b"peachnote-vault/v1\0ns\0scope\0");
}

#[test]
fn aad_with_extra() {
    let aad = build_namespaced_aad("ns", "scope", 1, Some(b"extra")).unwrap();
    let mut expected = b"peachnote-vault/v1\0ns\0scope\0".to_vec();
    expected.extend_from_slice(b"extra");
    assert_eq!(aad, expected);
}

#[test]
fn aad_changes_with_version() {
    let a = build_namespaced_aad("ns", "scope", 1, None).unwrap();
    let b = build_namespaced_aad("ns", "scope", 2, None).unwrap();
    assert_ne!(a, b);
}

#[test]
fn derived_key_is_256_bit() {
    let k = derive_namespaced_key(&[0u8; 32], "ns", "scope", 1).unwrap();
    assert_eq!(k.len(), 32);
}
