use peachnote_vault_core::crypto::{
    decode_envelope, encode_envelope, open_namespaced, seal_namespaced,
};
use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn encrypt_decrypt_real_txt_file() {
    let path = fixtures_dir().join("sample.txt");
    let original = fs::read(&path).expect("failed to read sample.txt");
    let original_str = String::from_utf8_lossy(&original);

    println!("=== Original TXT ({} bytes) ===", original.len());
    println!("{original_str}");

    let root_key = [0xABu8; 32];
    let filename_aad = path.file_name().unwrap().as_encoded_bytes();

    let envelope = seal_namespaced(
        &root_key,
        "vault.notes",
        "files/txt",
        &original,
        Some(filename_aad),
        1,
    )
    .expect("seal txt file");

    println!("=== Envelope ===");
    println!("algorithm : {}", envelope.algorithm);
    println!("key_version: {}", envelope.key_version);
    println!("nonce (hex): {}", hex(&envelope.nonce));
    println!(
        "ciphertext : {} bytes (first 32 hex: {})",
        envelope.ciphertext.len(),
        hex(&envelope.ciphertext[..envelope.ciphertext.len().min(32)])
    );

    // encode -> base64 transport form
    let encoded = encode_envelope(&envelope);
    println!("\n=== Encoded (base64 transport) ===");
    println!("nonce_base64     : {}", encoded.nonce_base64);
    println!(
        "ciphertext_base64: {}...",
        &encoded.ciphertext_base64[..encoded.ciphertext_base64.len().min(60)]
    );

    // decode back
    let decoded = decode_envelope(&encoded).expect("decode envelope");
    assert_eq!(decoded, envelope);
    println!("\n=== Decode check: OK (envelope matches) ===");

    // decrypt
    let decrypted = open_namespaced(
        &root_key,
        "vault.notes",
        "files/txt",
        &decoded,
        Some(filename_aad),
    )
    .expect("open txt file");

    let decrypted_str = String::from_utf8_lossy(&decrypted);
    println!("\n=== Decrypted TXT ({} bytes) ===", decrypted.len());
    println!("{decrypted_str}");

    assert_eq!(decrypted, original, "decrypted content must match original");
    println!("\n=== PASS: txt round-trip identical ===");
}

#[test]
fn encrypt_decrypt_real_md_file() {
    let path = fixtures_dir().join("sample.md");
    let original = fs::read(&path).expect("failed to read sample.md");
    let original_str = String::from_utf8_lossy(&original);

    println!("=== Original MD ({} bytes) ===", original.len());
    println!("{original_str}");

    let root_key = [0xCDu8; 32];
    let filename_aad = path.file_name().unwrap().as_encoded_bytes();

    let envelope = seal_namespaced(
        &root_key,
        "vault.notes",
        "files/md",
        &original,
        Some(filename_aad),
        1,
    )
    .expect("seal md file");

    println!("=== Envelope ===");
    println!("algorithm : {}", envelope.algorithm);
    println!("key_version: {}", envelope.key_version);
    println!("nonce (hex): {}", hex(&envelope.nonce));
    println!(
        "ciphertext : {} bytes (first 32 hex: {})",
        envelope.ciphertext.len(),
        hex(&envelope.ciphertext[..envelope.ciphertext.len().min(32)])
    );

    let encoded = encode_envelope(&envelope);
    println!("\n=== Encoded (base64 transport) ===");
    println!("nonce_base64     : {}", encoded.nonce_base64);
    println!(
        "ciphertext_base64: {}...",
        &encoded.ciphertext_base64[..encoded.ciphertext_base64.len().min(60)]
    );

    let decoded = decode_envelope(&encoded).expect("decode envelope");
    assert_eq!(decoded, envelope);
    println!("\n=== Decode check: OK (envelope matches) ===");

    let decrypted = open_namespaced(
        &root_key,
        "vault.notes",
        "files/md",
        &decoded,
        Some(filename_aad),
    )
    .expect("open md file");

    let decrypted_str = String::from_utf8_lossy(&decrypted);
    println!("\n=== Decrypted MD ({} bytes) ===", decrypted.len());
    println!("{decrypted_str}");

    assert_eq!(decrypted, original, "decrypted content must match original");
    println!("\n=== PASS: md round-trip identical ===");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
