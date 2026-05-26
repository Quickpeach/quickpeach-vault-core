//! Audit: confirm Argon2id KDF parameters for recovery bundles meet
//! OWASP 2024 guidance, and that bundles serialized with the OWASP
//! minimum parameters (which would be considered "legacy" relative to
//! the current 256 MiB default) still open successfully.
//!
//! Iteration TTT — KDF parameter audit. The bundle wire format carries
//! `memory_kib`, `iterations`, and `parallelism` inline (see
//! `src/format.rs` binary layout), so older bundles authored with lower
//! params remain openable indefinitely. This test pins that contract.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use peachnote_vault_core::recovery::{
    build_recovery_bundle, derive_recovery_wrap_key, encode_recovery_bundle_document,
    generate_recovery_phrase, open_recovery_bundle, RecoveryBundleDocument, RecoveryBundleKdf,
    RECOVERY_AAD, RECOVERY_ARGON2_ITERATIONS, RECOVERY_ARGON2_MEMORY_KIB,
    RECOVERY_ARGON2_PARALLELISM, RECOVERY_BUNDLE_FORMAT, RECOVERY_BUNDLE_VERSION,
    RECOVERY_KDF_ALGORITHM, RECOVERY_SALT_LEN,
};
use peachnote_vault_core::{encode_envelope, seal_with_key, VaultEnvelope};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// OWASP 2024 Argon2id baseline for password storage in a non-hot-path
/// context (see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
/// — Argon2id recommendation: m=19 MiB (preferred 64 MiB), t=2, p=1 minimum;
/// the more conservative second-row recommendation is m=64 MiB, t=3, p=4).
/// QuickPeach recovery-phrase derivation is a one-time interactive cost,
/// so we target the conservative row.
const OWASP_2024_MIN_MEMORY_KIB: u32 = 64 * 1024;
const OWASP_2024_MIN_ITERATIONS: u32 = 3;
const OWASP_2024_MIN_PARALLELISM: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuditPayload {
    note: String,
}

// Compile-time guard — if any default constant drops below the OWASP
// 2024 floor, the test binary will fail to compile. This is strictly
// stronger than a runtime `#[test]` and is what clippy nudges toward
// for assertions on `const` operands.
const _: () = {
    assert!(
        RECOVERY_ARGON2_MEMORY_KIB >= OWASP_2024_MIN_MEMORY_KIB,
        "Argon2id memory cost is below OWASP 2024 floor"
    );
    assert!(
        RECOVERY_ARGON2_ITERATIONS >= OWASP_2024_MIN_ITERATIONS,
        "Argon2id iterations is below OWASP 2024 floor"
    );
    assert!(
        RECOVERY_ARGON2_PARALLELISM >= OWASP_2024_MIN_PARALLELISM,
        "Argon2id parallelism is below OWASP 2024 floor"
    );
};

/// Smoke marker so `cargo test` surfaces this audit module in its
/// output. The actual OWASP-floor enforcement happens in the
/// `const _` block above and is checked at compile time.
#[test]
fn argon2id_floor_audit_compiled() {
    // If this binary compiled, the floor guard passed.
}

#[test]
fn new_bundles_use_current_defaults() {
    let phrase = generate_recovery_phrase().unwrap();
    let payload = AuditPayload {
        note: "current-defaults".into(),
    };

    let bundle = build_recovery_bundle(&payload, &phrase).unwrap();
    let decoded = open_recovery_bundle::<AuditPayload>(&bundle, &phrase).unwrap();

    assert_eq!(decoded.document.kdf.memory_kib, RECOVERY_ARGON2_MEMORY_KIB);
    assert_eq!(decoded.document.kdf.iterations, RECOVERY_ARGON2_ITERATIONS);
    assert_eq!(
        decoded.document.kdf.parallelism,
        RECOVERY_ARGON2_PARALLELISM
    );
    assert_eq!(decoded.payload, payload);
}

/// Forge a bundle with the OWASP-minimum (lower) Argon2id parameters,
/// simulating a "legacy" bundle from a hypothetical earlier release with
/// weaker defaults. The current decoder must still open it because the
/// wire format carries the KDF params inline.
#[test]
fn legacy_lower_param_bundles_still_open() {
    let phrase = generate_recovery_phrase().unwrap();
    let payload = AuditPayload {
        note: "legacy-params".into(),
    };

    let mut salt = [0u8; RECOVERY_SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let wrap_key = derive_recovery_wrap_key(
        &phrase,
        &salt,
        OWASP_2024_MIN_MEMORY_KIB,
        OWASP_2024_MIN_ITERATIONS,
        OWASP_2024_MIN_PARALLELISM,
    )
    .unwrap();

    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let envelope: VaultEnvelope = seal_with_key(
        &wrap_key,
        &payload_bytes,
        RECOVERY_AAD,
        RECOVERY_BUNDLE_VERSION,
    )
    .unwrap();

    let document = RecoveryBundleDocument {
        format: RECOVERY_BUNDLE_FORMAT.to_string(),
        version: RECOVERY_BUNDLE_VERSION,
        kdf: RecoveryBundleKdf {
            algorithm: RECOVERY_KDF_ALGORITHM.to_string(),
            salt_base64: BASE64_STANDARD.encode(salt),
            memory_kib: OWASP_2024_MIN_MEMORY_KIB,
            iterations: OWASP_2024_MIN_ITERATIONS,
            parallelism: OWASP_2024_MIN_PARALLELISM,
        },
        envelope: encode_envelope(&envelope),
    };

    let bundle = encode_recovery_bundle_document(&document).unwrap();
    let decoded = open_recovery_bundle::<AuditPayload>(&bundle, &phrase).unwrap();

    assert_eq!(decoded.payload, payload);
    // The decoded bundle must reflect the params that were actually
    // serialized into it — NOT the current crate defaults.
    assert_eq!(decoded.document.kdf.memory_kib, OWASP_2024_MIN_MEMORY_KIB);
    assert_eq!(decoded.document.kdf.iterations, OWASP_2024_MIN_ITERATIONS);
    assert_eq!(decoded.document.kdf.parallelism, OWASP_2024_MIN_PARALLELISM);
}
