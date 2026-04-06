use thiserror::Error;

pub const VAULT_ALGORITHM_XCHACHA20POLY1305: &str = "xchacha20poly1305";

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultCryptoError {
    #[error("namespace must not be empty")]
    EmptyNamespace,
    #[error("scope must not be empty")]
    EmptyScope,
    #[error("scope is too long")]
    ScopeTooLong,
    #[error("scope contains unsupported characters")]
    InvalidScope,
    #[error("unsupported vault algorithm '{0}'")]
    UnsupportedAlgorithm(String),
    #[error("invalid envelope nonce length")]
    InvalidNonceLength,
    #[error("invalid base64 envelope field: {0}")]
    InvalidBase64(String),
    #[error("key version must be >= 1")]
    InvalidKeyVersion,
    #[error("hkdf expansion failed")]
    KeyDerivation,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

pub use crate::format::{decode_envelope, encode_envelope, EncodedVaultEnvelope, VaultEnvelope};
pub use crate::primitives::{
    aead::{open_with_key, seal_with_key},
    kdf::{build_namespaced_aad, derive_namespaced_key},
};
pub use crate::protocol::{open_namespaced, seal_namespaced};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_namespaced_envelope() {
        let root_key = [7u8; 32];
        let aad = b"metadata";
        let envelope = seal_namespaced(
            &root_key,
            "extension.demo",
            "storage/blob",
            b"hello world",
            Some(aad),
            1,
        )
        .expect("seal");

        let opened = open_namespaced(
            &root_key,
            "extension.demo",
            "storage/blob",
            &envelope,
            Some(aad),
        )
        .expect("open");

        assert_eq!(opened, b"hello world");
    }

    #[test]
    fn round_trips_txt_file() {
        let root_key = [42u8; 32];
        let txt_content = b"This is a plain text note.\nLine two of the note.\n";
        let filename_aad = b"notes/hello.txt";

        let envelope = seal_namespaced(
            &root_key,
            "vault.notes",
            "files/txt",
            txt_content,
            Some(filename_aad),
            1,
        )
        .expect("seal txt");

        assert_ne!(envelope.ciphertext, txt_content.to_vec());

        let decrypted = open_namespaced(
            &root_key,
            "vault.notes",
            "files/txt",
            &envelope,
            Some(filename_aad),
        )
        .expect("open txt");

        assert_eq!(decrypted, txt_content.to_vec());
    }

    #[test]
    fn round_trips_md_file() {
        let root_key = [55u8; 32];
        let md_content =
            b"# My Note\n\nSome **bold** and *italic* text.\n\n- bullet one\n- bullet two\n";
        let filename_aad = b"notes/readme.md";

        let envelope = seal_namespaced(
            &root_key,
            "vault.notes",
            "files/md",
            md_content,
            Some(filename_aad),
            1,
        )
        .expect("seal md");

        assert_ne!(envelope.ciphertext, md_content.to_vec());

        let decrypted = open_namespaced(
            &root_key,
            "vault.notes",
            "files/md",
            &envelope,
            Some(filename_aad),
        )
        .expect("open md");

        assert_eq!(decrypted, md_content.to_vec());
    }

    #[test]
    fn txt_decrypt_fails_with_wrong_key() {
        let root_key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let txt_content = b"secret text content";

        let envelope = seal_namespaced(&root_key, "vault.notes", "files/txt", txt_content, None, 1)
            .expect("seal");

        let result = open_namespaced(&wrong_key, "vault.notes", "files/txt", &envelope, None);

        assert!(result.is_err());
    }

    #[test]
    fn md_decrypt_fails_with_tampered_ciphertext() {
        let root_key = [55u8; 32];
        let md_content = b"# Secret heading\n";

        let mut envelope =
            seal_namespaced(&root_key, "vault.notes", "files/md", md_content, None, 1)
                .expect("seal");

        envelope.ciphertext[0] ^= 0xFF;

        let result = open_namespaced(&root_key, "vault.notes", "files/md", &envelope, None);

        assert!(result.is_err());
    }

    #[test]
    fn txt_and_md_encode_decode_round_trip() {
        let root_key = [10u8; 32];

        let txt_envelope = seal_namespaced(
            &root_key,
            "vault.notes",
            "files/txt",
            b"plain text",
            None,
            1,
        )
        .expect("seal txt");

        let md_envelope =
            seal_namespaced(&root_key, "vault.notes", "files/md", b"# markdown", None, 1)
                .expect("seal md");

        let encoded_txt = encode_envelope(&txt_envelope);
        let decoded_txt = decode_envelope(&encoded_txt).expect("decode txt");
        assert_eq!(decoded_txt, txt_envelope);

        let encoded_md = encode_envelope(&md_envelope);
        let decoded_md = decode_envelope(&encoded_md).expect("decode md");
        assert_eq!(decoded_md, md_envelope);
    }

    #[test]
    fn encodes_and_decodes_transport_envelope() {
        let root_key = [9u8; 32];
        let envelope = seal_namespaced(
            &root_key,
            "extension.demo",
            "storage/blob",
            b"bytes",
            None,
            1,
        )
        .expect("seal");

        let encoded = encode_envelope(&envelope);
        let decoded = decode_envelope(&encoded).expect("decode");

        assert_eq!(decoded, envelope);
    }
}
