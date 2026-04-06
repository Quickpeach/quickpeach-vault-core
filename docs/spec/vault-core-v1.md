# Vault Core v1

How Peach Note encrypts your data, and what must never change.

## Why this document exists

`peachnote-vault-core` is a custom encryption layer. Unlike something
like age, there is no public standard behind it. That means the only
thing protecting users from silent data-loss regressions is this spec
and the tests that pin it.

If you upgrade a dependency, change a string constant, or refactor
serialization — and any of the frozen values below change — users lose
access to their notes. Treat every section below as a contract.

## What this covers

- How keys are derived from the master key
- How data is encrypted and packaged
- How recovery bundles wrap the master key
- How manifest hashes are computed

This does not cover OS keychain integration, Stronghold, sync, or UI.
Those can change freely without breaking encrypted data on disk.

---

## Envelope

Every encrypted object is stored as a **vault envelope**.

The cipher is XChaCha20-Poly1305 (24-byte nonce, 16-byte Poly1305 tag
appended to ciphertext). The algorithm identifier is the literal string
`xchacha20poly1305`. Readers reject anything else.

In-memory shape:

```
algorithm:   "xchacha20poly1305"
keyVersion:  u32
nonce:       [u8; 24]      — random, generated per seal
ciphertext:  Vec<u8>       — encrypted payload + 16-byte tag
```

On the wire (JSON transport), nonce and ciphertext are base64-encoded:

```json
{
  "algorithm": "xchacha20poly1305",
  "keyVersion": 1,
  "nonceBase64": "...",
  "ciphertextBase64": "..."
}
```

These field names are frozen. Renaming them breaks every existing
encrypted file.

---

## Key Derivation

The master data key (MDK) is 32 random bytes. It never encrypts
anything directly. Instead, each object gets its own key via HKDF:

```
HKDF-SHA256(
  ikm  = MDK,
  salt = namespace (UTF-8 bytes, trimmed),
  info = "peachnote/vault/{namespace}/{scope}/v{key_version}",
  len  = 32
)
```

The info string format is frozen. Changing a single character in it
changes every derived key, which means every existing encrypted note
becomes unreadable.

### Input rules

Namespace: trimmed, must not be empty.

Scope: trimmed, must not be empty, max 128 characters, ASCII
alphanumeric plus `. : _ - /` only.

### Pinned test vector

```
root key:    0b0b0b0b 0b0b0b0b 0b0b0b0b 0b0b0b0b
             0b0b0b0b 0b0b0b0b 0b0b0b0b 0b0b0b0b
namespace:   test-ns
scope:       test-scope
key version: 1

derived key: a2b3d713 176bada0 18eead33 3a144c58
             6f69bc49 3fa7d496 bef47388 14100f67
```

If `cargo test pinned_derivation_does_not_drift` fails after a
dependency upgrade, stop. Do not release.

---

## AAD (Authenticated Additional Data)

Every seal binds metadata into the ciphertext authentication. The AAD
byte string is:

```
peachnote-vault/v{key_version}\0{namespace}\0{scope}\0{extra_aad}
```

The null bytes (`\0`) are literal separators. `extra_aad` is optional
and appended raw. This format is frozen — if you change it, existing
ciphertext will fail authentication on open.

Example for namespace `quickpeach.notes`, scope `note/abc`, version 1,
no extra AAD:

```
peachnote-vault/v1\0quickpeach.notes\0note/abc\0
```

---

## Recovery Bundle

The recovery bundle lets users move their MDK to a new device using a
24-word phrase. It works like this:

1. Generate a 24-word BIP39 English mnemonic (256-bit entropy)
2. Derive a wrap key: `Argon2id(phrase, random_salt)`
3. Encrypt the MDK (and any other managed keys) with the wrap key
   using XChaCha20-Poly1305
4. Package everything into a PEM-armored text document whose body is
   base64-encoded binary

The emitted document looks like:

```
-----BEGIN QUICKPEACH RECOVERY BUNDLE-----
UVBSQgEBAAQAAAAAAwAAAAQQm...base64-encoded binary payload...==
-----END QUICKPEACH RECOVERY BUNDLE-----
```

After base64-decoding the PEM body, the binary layout is:

```
MAGIC      4 bytes   "QPRB"
VERSION    1 byte    0x01
KDF_ID     1 byte    0x01 = argon2id
MEM_KIB    4 bytes   big-endian
ITERS      4 bytes   big-endian
PAR        4 bytes   big-endian
SALT_LEN   1 byte
SALT       N bytes
AEAD_ID    1 byte    0x01 = xchacha20poly1305
KEY_VER    4 bytes   big-endian
NONCE      24 bytes
CIPHERTEXT remaining bytes, including 16-byte Poly1305 tag
```

Internally, readers reconstruct the equivalent logical document:

```json
{
  "format": "quickpeach-recovery-bundle",
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "saltBase64": "...",
    "memoryKib": 262144,
    "iterations": 3,
    "parallelism": 4
  },
  "envelope": {
    "algorithm": "xchacha20poly1305",
    "keyVersion": 1,
    "nonceBase64": "...",
    "ciphertextBase64": "..."
  }
}
```

### What is frozen

- Format string: `quickpeach-recovery-bundle`
- Header/footer markers: exactly as shown above
- Binary magic: `QPRB`
- Binary version byte: `0x01`
- KDF algorithm: `argon2id`
- Default parameters: 256 MB memory, 3 iterations, parallelism 4,
  16-byte salt
- AEAD identifier: `0x01 = xchacha20poly1305`
- Recovery AAD: the literal bytes `quickpeach-recovery-bundle-v1`
- Phrase: exactly 24 English BIP39 words

Readers must reject unknown `format`, `version`, or `kdf.algorithm`.
Writers emit binary PEM. Parsers must accept both the current binary
PEM form and the older JSON forms (JSON inside PEM or raw JSON) for
backward compatibility.

---

## Manifest Hashing

Each encrypted object has a manifest that tracks its identity, version,
chunks, and hash chain. The manifest hash is:

```
SHA-256(serde_json::to_vec(manifest))  →  lowercase hex
```

This means the exact JSON field names, their order (as determined by
serde), and the enum serialization strategy (kebab-case for
`VaultManifestKind`) are all part of the compatibility surface.

The `previousManifestHash` field links versions into a chain. If
someone tampers with a previous hash, the current manifest hash changes,
which is how you detect rollback.

If you add or rename a field in `VaultManifest`, existing manifest
hashes will change. That requires an explicit migration, not a silent
update.

---

## XChaCha20-Poly1305 Known-Answer Test

From draft-irtf-cfrg-xchacha-03 section A.3.1. This vector is checked
in `tests/crypto_adversarial.rs::rfc_vector_exact_ciphertext_and_open`
to verify the underlying cipher implementation has not drifted.

```
key:       80818283 84858687 88898a8b 8c8d8e8f
           90919293 94959697 98999a9b 9c9d9e9f

nonce:     40414243 44454647 48494a4b 4c4d4e4f
           50515253 54555657

aad:       50515253 c0c1c2c3 c4c5c6c7

plaintext: "Ladies and Gentlemen of the class of '99:
            If I could offer you only one tip for the
            future, sunscreen would be it."

ciphertext (including Poly1305 tag):
           bd6d179d 3e83d43b 95765794 93c0e939
           572a1700 252bfacc bed2902c 21396cbb
           731c7f1b 0b4aa644 0bf3a82f 4eda7e39
           ae64c670 8c54c216 cb96b72e 1213b452
           2f8c9ba4 0db5d945 b11b69b9 82c1bb9e
           3f3fac2b c369488f 76b23835 65d3fff9
           21f9664c 97637da9 768812f6 15c68b13
           b52ec087 5924c1c7 987947de afd8780a cf49
```

---

## Upgrade Rules

Before releasing any dependency update that touches crypto or serde:

1. Run `cargo test` — all pinned vectors, RFC KATs, and fixture
   round-trips must pass
2. Run the compatibility fixture tests (see `tests/fixtures/`)
3. If anything fails, do not release. Figure out what changed and
   whether it is a real break or a test bug
4. If it is a real format change, bump to v2 with an explicit migration
   path. Do not silently change v1 behavior

Before releasing any change to `VaultManifest` struct fields:

1. Check that existing manifest hashes are stable
2. If a field is added, it must be `#[serde(default)]` so old manifests
   still parse and hash identically
3. If a field is renamed or removed, that is a v2 change

---

## Verification Status

This repository now includes:

- Checked-in compatibility fixtures under `tests/fixtures/compat/`
- Fuzz targets for envelope decoding, recovery bundle parsing, and
  seal/open round trips under `fuzz/fuzz_targets/`

Still worth doing later:

- External review of composition and versioning
