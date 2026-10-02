# tc_buffered_cipher

[![crates.io](https://img.shields.io/crates/v/tc_buffered_cipher.svg)](https://crates.io/crates/tc_buffered_cipher)
[![docs.rs](https://docs.rs/tc_buffered_cipher/badge.svg)](https://docs.rs/tc_buffered_cipher)
[![CI](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

One buffered interface over block modes with or without padding, stream
ciphers and AEADs, after Bouncy Castle's `IBufferedCipher`. `no_std`, no
`unsafe`, Rust 1.85 or later.

## Types

- `FixedBufferedBlockCipher`, `BufferedBlockCipher` (`alloc`) — a block mode
  buffered to whole blocks.
- `FixedPaddedBufferedBlockCipher`, `PaddedBufferedBlockCipher` (`alloc`) — the
  same with padding, PKCS#7 by default.
- `BufferedStreamCipher` — a stream cipher.
- `BufferedAeadBlockCipher`, `BufferedAeadCipher` — an AEAD over a block
  cipher, or one that carries its own primitive.
- `CipherDirection` — encryption or decryption.
- `BufferedError` — the failures of the block and stream adapters.

## Traits

- `BufferedCipher` — sizing, `process_bytes`, `do_final` and `reset`.
- `BufferedCipherInit` — starts a message from parameters of type `P`.

## Features

- `alloc` (off by default) — the block adapters sized at run time.

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

## Security

Padded decryption is a padding oracle: the length it writes and a
`CorruptPadding` error reveal the padding. Authenticate CBC ciphertext before
decrypting it, or use an AEAD. Each adapter is constant time exactly when the
cipher it wraps is; the documentation states the timing of every item.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
