# tc_crypto

A Rust workspace for crates that build on the block-cipher, stream-cipher,
AEAD and asymmetric-block-cipher contracts together:
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher),
[`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher),
[`tc_aead_cipher`](https://crates.io/crates/tc_aead_cipher) and
[`tc_asym_cipher`](https://crates.io/crates/tc_asym_cipher). It holds
`tc_buffered_cipher`, which puts all four families behind one buffered
interface, `tc_cts_modes`, cipher text stealing behind that
interface, and `tc_drbg`, the SP 800-90A random bit generators over those
primitives. Each crate is published separately and keeps its own README,
changelog, and validation commands.

[![CI](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_buffered_cipher`](tc_buffered_cipher) | [![crates.io](https://img.shields.io/crates/v/tc_buffered_cipher.svg)](https://crates.io/crates/tc_buffered_cipher) [![docs.rs](https://docs.rs/tc_buffered_cipher/badge.svg)](https://docs.rs/tc_buffered_cipher) | The `BufferedCipher` and `BufferedCipherInit` contracts, the Rust form of Bouncy Castle's `IBufferedCipher`, with adapters for block modes with or without padding, stream ciphers, AEADs and asymmetric block ciphers. `no_std`, no `unsafe`; a default-off `alloc` feature adds adapters sized at run time. Constant time exactly when the wrapped cipher is; padded decryption is a padding oracle and is documented as one. |
| [`tc_cts_modes`](tc_cts_modes) | [![crates.io](https://img.shields.io/crates/v/tc_cts_modes.svg)](https://crates.io/crates/tc_cts_modes) [![docs.rs](https://docs.rs/tc_cts_modes/badge.svg)](https://docs.rs/tc_cts_modes) | Cipher text stealing over ECB and CBC, Bouncy Castle's `CtsBlockCipher`, behind the `BufferedCipher` interface: a ciphertext as long as a plaintext of at least one block. `no_std`, no `unsafe`; a default-off `alloc` feature adds the form sized at run time. Constant time exactly when the block cipher is. |
| [`tc_drbg`](tc_drbg) | [![crates.io](https://img.shields.io/crates/v/tc_drbg.svg)](https://crates.io/crates/tc_drbg) [![docs.rs](https://docs.rs/tc_drbg/badge.svg)](https://docs.rs/tc_drbg) | NIST SP 800-90A HMAC_DRBG, Hash_DRBG and AES CTR_DRBG, Bouncy Castle's SP800 DRBGs, seeded from a caller's `rand_core` source and usable as one: limits are errors, never panics. `no_std`, no `unsafe`, no allocator. Constant time exactly when the MAC, digest or block cipher is; the state is wiped on drop. |

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and
reaches the heap only through its default-off `alloc` feature.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build, since every dependency is a `tc_*` crate or `rand_core` 0.10,
which declares 1.85 too; dev-dependencies used only by tests are exempt. The workspace lock tracks the latest dependency
releases, so CI on stable tests what a user on a current toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, checks the `wasm32-unknown-unknown` and `aarch64-unknown-none`
targets and each crate's dependency set on each target, checks the build on
Rust 1.85.0, and verifies the package archive. See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

Before a release, check each archive and run publication validation from a
committed checkout:

```text
cargo package -p <crate> --list --locked
cargo publish -p <crate> --dry-run --locked
```

The archive must include both license texts, the crate README, the changelog,
the source and the integration tests, and no `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
