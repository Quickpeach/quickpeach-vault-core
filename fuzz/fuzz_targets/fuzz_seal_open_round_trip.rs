#![no_main]
use libfuzzer_sys::fuzz_target;
use peachnote_vault_core::crypto::{open_with_key, seal_with_key};

// Property: for any plaintext and AAD, seal then open must return the
// original plaintext. If this ever fails, the cipher or envelope
// plumbing is broken.

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 { return; }

    // Use first 32 bytes as key, rest as plaintext.
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let plaintext = &data[32..];
    let aad = b"fuzz-aad";

    let Ok(envelope) = seal_with_key(&key, plaintext, aad, 1) else { return };
    let Ok(decrypted) = open_with_key(&key, &envelope, aad) else {
        panic!("seal succeeded but open failed — round-trip broken");
    };
    assert_eq!(decrypted, plaintext, "round-trip mismatch");
});
