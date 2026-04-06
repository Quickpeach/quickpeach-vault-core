# Fuzzing

`peachnote-vault-core` keeps fuzz targets for parser and crypto round-trip safety.

## Targets

- `fuzz_decode_envelope`
- `fuzz_recovery_parse`
- `fuzz_seal_open_round_trip`

## Prerequisites

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Run a target

```bash
cargo +nightly fuzz run fuzz_decode_envelope
cargo +nightly fuzz run fuzz_recovery_parse
cargo +nightly fuzz run fuzz_seal_open_round_trip
```

## Notes

- corpora live under `fuzz/corpus/`
- crash artifacts live under `fuzz/artifacts/`
- CI only checks that the fuzz crate compiles; actual fuzz campaigns are meant to be run manually or in dedicated longer-running jobs
