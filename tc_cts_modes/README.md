# tc_cts_modes

[![crates.io](https://img.shields.io/crates/v/tc_cts_modes.svg)](https://crates.io/crates/tc_cts_modes)
[![docs.rs](https://docs.rs/tc_cts_modes/badge.svg)](https://docs.rs/tc_cts_modes)
[![CI](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Cipher text stealing over ECB and CBC, after Bouncy Castle's `CtsBlockCipher`:
a message of any length of at least one block, with a ciphertext as long as
the plaintext, behind the `BufferedCipher` interface of `tc_buffered_cipher`.
`no_std`, no `unsafe`, Rust 1.85 or later.

## Types

- `FixedCtsBlockCipher` — CTS over a block cipher of `N`-byte blocks, with its
  buffers inline.
- `CtsBlockCipher` (`alloc`) — the same, sized from the block size at run time.
- `Ecb`, `Cbc` — the chaining under CTS; `Cbc` takes an IV.

## Traits

- `CtsChaining` — sealed; implemented by `Ecb` and `Cbc`.

## Features

- `alloc` (off by default) — `CtsBlockCipher`.

## Usage

```toml
[dependencies]
tc_cts_modes = "0.1.0"
tc_buffered_cipher = "0.2.0"
tc_block_modes = "0.1.0"
tc_aes = "0.1.0"
```

```rust
use tc_aes::AesEngine;
use tc_block_modes::KeyWithIvRef;
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};
use tc_cts_modes::{Cbc, FixedCtsBlockCipher};

let mut cipher = FixedCtsBlockCipher::<_, 16, Cbc>::cbc(AesEngine::new());
cipher.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&[0x42; 16], &[0x24; 16])).expect("valid key and IV");
let mut sealed = [0; 21];
let written = cipher.process_bytes(b"twenty-one bytes long", &mut sealed).expect("initialized");
cipher.do_final(&mut sealed[written..]).expect("at least one whole block");
```

## Security

CTS does not authenticate: a changed ciphertext decrypts to garbage without an
error. Authenticate the ciphertext first, or use an AEAD. Each type is
constant time exactly when the block cipher it holds is; the documentation
states the timing of every item.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
