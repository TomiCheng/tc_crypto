# tc_buffered_cipher

[![crates.io](https://img.shields.io/crates/v/tc_buffered_cipher.svg)](https://crates.io/crates/tc_buffered_cipher)
[![docs.rs](https://docs.rs/tc_buffered_cipher/badge.svg)](https://docs.rs/tc_buffered_cipher)
[![CI](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

One buffered interface over block modes with or without padding, stream
ciphers and AEADs: the `BufferedCipher` and `BufferedCipherInit` contracts,
the Rust form of Bouncy Castle's `IBufferedCipher`, and the adapters that put
the modes of [`tc_block_modes`](https://crates.io/crates/tc_block_modes), the
engines of [`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher)
and the AEADs of [`tc_aead_cipher`](https://crates.io/crates/tc_aead_cipher)
behind them. Ported from Bouncy Castle C#.

The crate is `no_std`, needs no allocator by default and contains no `unsafe`
code. It depends on those three crates,
[`tc_block_cipher`](https://crates.io/crates/tc_block_cipher),
[`tc_block_padding`](https://crates.io/crates/tc_block_padding) and
[`tc_zeroize`](https://crates.io/crates/tc_zeroize).

Requires Rust 1.85 or later (edition 2024).

## Types

- `FixedBufferedBlockCipher`, `BufferedBlockCipher` (`alloc`) — a block mode
  buffered to whole blocks; Bouncy Castle's `BufferedBlockCipher`.
- `FixedPaddedBufferedBlockCipher`, `PaddedBufferedBlockCipher` (`alloc`) — a
  block mode whose final block is padded, PKCS#7 by default; Bouncy Castle's
  `PaddedBufferedBlockCipher`.
- `BufferedStreamCipher` — a stream cipher; Bouncy Castle's
  `BufferedStreamCipher`.
- `BufferedAeadBlockCipher`, `BufferedAeadCipher` — an AEAD mode over a block
  cipher, or an AEAD that carries its own primitive; Bouncy Castle's
  `BufferedAeadBlockCipher` and `BufferedAeadCipher`.
- `CipherDirection` — encryption or decryption, converting to and from the
  block-cipher and stream-cipher contracts' own directions.
- `BufferedError` — the failures of the block and stream adapters.

Every adapter takes input in pieces of any size, holds back what its cipher
cannot process yet and finishes in `do_final`; `update_output_len` and
`output_len` say how much a call writes. The `Fixed` forms keep their blocks
inline and take the block size as a const parameter; the others size their
buffers from the mode at run time. A completed final block of a padded adapter
waits for `do_final`, and a full one is followed by a block of padding alone
whatever the scheme, as in Bouncy Castle. `new` takes PKCS#7, and
`with_padding` any `tc_block_padding` scheme.

The stream adapter writes as much as it reads and restarts its keystream in
`do_final`. The AEAD adapters pass every call to the engine and keep its
error type, so a failed tag check or a refused nonce reuse arrives unchanged;
associated data goes in only as the initial associated data of the
parameters, as in Bouncy Castle.

## Traits

- `BufferedCipher` — sizing, `process_bytes`, `do_final` and `reset` over
  caller-provided buffers.
- `BufferedCipherInit` — starts a message in a direction from parameters of
  type `P`.

## Features

- `alloc` (off by default) — adds `BufferedBlockCipher` and
  `PaddedBufferedBlockCipher`; does not require the standard library.

## Usage

```toml
[dependencies]
tc_buffered_cipher = "0.1.0"
tc_block_modes = "0.1.0"
tc_aes = "0.1.0"
```

```rust
use tc_aes::AesEngine;
use tc_block_modes::{FixedCbcBlockCipher, KeyWithIvRef};
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection, FixedPaddedBufferedBlockCipher};

let mode = FixedCbcBlockCipher::<_, 16>::new(AesEngine::new());
let mut cipher = FixedPaddedBufferedBlockCipher::<_, 16>::new(mode);
cipher.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&[0x42; 16], &[0x24; 16])).expect("valid key and IV");
let mut sealed = [0; 16];
let written = cipher.process_bytes(b"attack at dawn", &mut sealed).expect("initialized");
cipher.do_final(&mut sealed[written..]).expect("room for the final block");
```

The type documentation carries an executable example for every adapter.

## Security

Padded decryption is a padding oracle: the length it writes reveals the
padding length, and `CorruptPadding` whether the padding was valid. An attacker
who can submit ciphertexts and observe either can decrypt CBC traffic, so
authenticate the ciphertext before decrypting it, or use an AEAD through the
AEAD adapters instead.

Every adapter is constant time exactly when the cipher it wraps is: the
buffering branches and copies only on lengths, which are public, and padding
is added and checked by `tc_block_padding`'s constant-time schemes, apart from
what padded decryption reveals. `tc_aes::AesEngine`, for example, is constant
time with AES-NI or its `rustcrypto` feature and variable time otherwise.
Nonce management belongs to the engines: the AEAD engines of
`tc_aead_cipher` refuse a repeated key and nonce on one instance, but nothing
tracks nonces across instances.

The block adapters wipe their buffered block and scratch block on reset and on
drop; the allocating forms size those buffers once and never grow them.
Wiping does not reach the caller's buffers or copies left in registers and on
the stack.

## Validation

The block adapters are tested over AES against the NIST SP 800-38A CBC and CTR
vectors and the FIPS-197 ECB vector, the padded adapters against CBC padded by
hand with PKCS#7 for every length up to three blocks, the stream adapter over
ChaCha20 against the RFC 8439 vector and the engine itself, and the AEAD block
adapter over GCM against test case 4 of the GCM specification. Every split of
the input into two pieces is checked, as are the errors for partial final
blocks, corrupt padding, failed tags, use before `init`, short outputs and
overflowing sizes. A test requires every public API to document whether it is
constant or variable time.

Missing public documentation and `unsafe` code are rejected by crate-level
lints.

Run these commands from the workspace root:

```text
cargo test -p tc_buffered_cipher --locked
cargo test -p tc_buffered_cipher --locked --all-features
cargo clippy -p tc_buffered_cipher --all-targets --all-features --locked -- -D warnings
cargo fmt -p tc_buffered_cipher --check
cargo doc -p tc_buffered_cipher --no-deps --all-features --locked
```

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_buffered_cipher --list --locked
cargo publish -p tc_buffered_cipher --dry-run --locked
```

The archive includes both license texts, this README, the changelog, the source
and the integration tests. It must not include `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
