# tc_crypto

A Rust workspace for crates that build on the block-cipher, stream-cipher and
AEAD contracts together:
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher),
[`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher) and
[`tc_aead_cipher`](https://crates.io/crates/tc_aead_cipher). It holds
`tc_buffered_cipher`, which puts all three families behind one buffered
interface. Each crate is published separately and keeps its own README,
changelog, and validation commands.

[![CI](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_buffered_cipher`](tc_buffered_cipher) | [![crates.io](https://img.shields.io/crates/v/tc_buffered_cipher.svg)](https://crates.io/crates/tc_buffered_cipher) [![docs.rs](https://docs.rs/tc_buffered_cipher/badge.svg)](https://docs.rs/tc_buffered_cipher) | The `BufferedCipher` and `BufferedCipherInit` contracts, the Rust form of Bouncy Castle's `IBufferedCipher`, with adapters for block modes with or without padding, stream ciphers and AEADs. `no_std`, no `unsafe`; a default-off `alloc` feature adds block adapters sized at run time. Constant time exactly when the wrapped cipher is; padded decryption is a padding oracle and is documented as one. |

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std` and
reaches the heap only through its default-off `alloc` feature.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build, since every dependency is a `tc_*` crate; dev-dependencies used
only by tests are exempt. The workspace lock tracks the latest dependency
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
