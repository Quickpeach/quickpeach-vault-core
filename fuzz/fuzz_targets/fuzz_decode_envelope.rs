#![no_main]
use libfuzzer_sys::fuzz_target;
use peachnote_vault_core::EncodedVaultEnvelope;
use peachnote_vault_core::crypto::decode_envelope;

// Feed arbitrary bytes as a JSON-ish string into decode_envelope.
// Goal: no panics, no UB. Errors are fine and expected.

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(encoded) = serde_json::from_str::<EncodedVaultEnvelope>(text) else { return };
    let _ = decode_envelope(&encoded);
});
