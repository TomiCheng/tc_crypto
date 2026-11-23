# tc_drbg

[![crates.io](https://img.shields.io/crates/v/tc_drbg.svg)](https://crates.io/crates/tc_drbg)
[![docs.rs](https://docs.rs/tc_drbg/badge.svg)](https://docs.rs/tc_drbg)
[![CI](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_crypto/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

NIST SP 800-90A deterministic random bit generators, after Bouncy Castle's
SP800 DRBGs: HMAC_DRBG, Hash_DRBG and AES CTR_DRBG, with the state inline and
no allocator. The caller supplies the entropy through `rand_core`.
`no_std`, no `unsafe`, Rust 1.85 or later.

## Types

- `HmacDrbg` — HMAC_DRBG over a `tc_macs` HMAC.
- `HashDrbg` — Hash_DRBG over a `tc_digest` SHA digest.
- `CtrDrbg` — CTR_DRBG over AES, with or without the derivation function.
- `DrbgError` — why creating, reseeding or drawing failed.

## Traits

- `Drbg` — `generate` and `reseed`, shared by the three generators.
- `rand_core::TryRng`, `rand_core::TryCryptoRng` — implemented by each
  generator with `DrbgError` as the error; wrap one in `rand_core::UnwrapErr`
  where a `CryptoRng` is required.

## Features

- None; everything works without an allocator.

## Usage

```toml
[dependencies]
tc_drbg = "0.1.0"
tc_macs = { version = "0.1.0", features = ["hmac", "alloc"] }
tc_sha = "0.1.1"
rand = "0.10"
```

```rust
use tc_drbg::{Drbg, HmacDrbg};
use tc_macs::Hmac;
use tc_sha::Sha256Digest;

let mut entropy = rand::rng();
let mut drbg = HmacDrbg::new(Hmac::new(Sha256Digest::new()), 256, 32, &mut entropy, b"nonce", &[])
    .expect("a SHA-256 HMAC supports 256 bits");
let mut key = [0; 32];
drbg.generate(&mut key, &[]).expect("a short request before the reseed limit");
```

## Security

A generator is only as good as the entropy it is seeded with. One request may
ask for at most 32 KiB, and after 2^47 requests every request fails until
`reseed`; both are errors, never panics. Each generator is constant time
exactly when its MAC, digest or block cipher is, and wipes its state on drop;
the documentation states the timing of every item.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
