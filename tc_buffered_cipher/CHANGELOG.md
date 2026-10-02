# Changelog

All notable changes to `tc_buffered_cipher` are documented in this file.

## 0.1.0 - 2026-10-02

Initial release.

### Added

- The `BufferedCipher` contract for sizing, `process_bytes`, `process_byte`,
  `do_final` and `reset` over caller-provided buffers, and
  `BufferedCipherInit`, which starts a message in a direction from parameters
  of type `P`; the Rust form of Bouncy Castle's `IBufferedCipher`.
- `CipherDirection`, which converts to and from the directions of
  `tc_block_cipher` and `tc_stream_cipher`, and `BufferedError`, which wraps
  the cipher's error and reports it through `source`.
- `FixedBufferedBlockCipher` and, with the default-off `alloc` feature,
  `BufferedBlockCipher`: a `tc_block_modes` mode buffered to whole blocks,
  finishing a partial block only for modes that allow one.
- `FixedPaddedBufferedBlockCipher` and, with `alloc`,
  `PaddedBufferedBlockCipher`: the same with a `tc_block_padding` scheme,
  PKCS#7 through `new` and any scheme through `with_padding`. A completed final
  block waits for `do_final`, and a full one is followed by a block of padding
  alone whatever the scheme.
- `from_cipher` on every block adapter, which wraps a bare block cipher in ECB
  mode as Bouncy Castle does.
- `BufferedStreamCipher` over a `tc_stream_cipher` engine, and
  `BufferedAeadBlockCipher` and `BufferedAeadCipher` over `tc_aead_cipher`
  engines, which keep the engine's own error type.
- `Display` for every adapter, writing the wrapped cipher's name, such as
  `"AES/CBC"`.
- Tests over AES against the NIST SP 800-38A CBC and CTR vectors and the
  FIPS-197 ECB vector, over CBC padded by hand with PKCS#7, over ChaCha20
  against the RFC 8439 vector and over GCM against test case 4 of the GCM
  specification, at every split of the input; tests of the error paths; a test
  that every public API documents whether it is constant or variable time; and
  doctests for every adapter.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- Depends on `tc_aead_cipher` 0.1, `tc_block_cipher` 0.1, `tc_block_modes`
  0.1, `tc_block_padding` 0.1, `tc_stream_cipher` 0.1 and `tc_zeroize` 0.1.
  Contains no `unsafe` code.
- Every adapter is constant time exactly when the cipher it wraps is; lengths
  are public. Padded decryption reveals the padding length and validity, a
  padding oracle.
- The `Fixed` block adapters panic in `new` when `N` differs from the mode's
  block size, and the allocating ones when the block size is zero.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
