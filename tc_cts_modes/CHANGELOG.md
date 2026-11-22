# Changelog

All notable changes to `tc_cts_modes` are documented in this file.

## 0.1.0 - Unreleased

### Added

- `FixedCtsBlockCipher`, cipher text stealing with its buffers inline, and,
  with `alloc`, `CtsBlockCipher`, which sizes them from the block size at run
  time: Bouncy Castle's `CtsBlockCipher` over any `tc_block_cipher` block
  cipher, behind `BufferedCipher` and `BufferedCipherInit` of
  `tc_buffered_cipher`. The ciphertext is as long as the plaintext, which needs
  at least one whole block.
- `Ecb` and `Cbc`, the chainings Bouncy Castle accepts, chosen by type: `Cbc`
  takes an IV of one block in `init` and gives the CBC-CTS of RFC 3962 beyond
  one block, `Ecb` takes the block cipher's parameters alone. `CtsChaining` is
  sealed.

### Compatibility

- Rust 1.85 or later; `no_std`, no `unsafe`, and no allocator without `alloc`.
- `FixedCtsBlockCipher::ecb` and `cbc` panic unless `N` is positive and equal
  to the block size of the block cipher, as the `Fixed` adapters of
  `tc_buffered_cipher` do.
