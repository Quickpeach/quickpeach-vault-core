#![no_main]
use libfuzzer_sys::fuzz_target;
use peachnote_vault_core::recovery::parse_recovery_bundle_document;

// Feed arbitrary strings into the recovery bundle parser.
// It must handle PEM wrappers, raw JSON, and total garbage without
// panicking or hitting UB.

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = parse_recovery_bundle_document(text);
});
