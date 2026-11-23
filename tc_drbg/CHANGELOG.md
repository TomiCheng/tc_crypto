# Changelog

All notable changes to `tc_drbg` are documented in this file.

## 0.1.0 - Unreleased

### Added

- `HmacDrbg`, `HashDrbg` and `CtrDrbg`: NIST SP 800-90A HMAC_DRBG, Hash_DRBG
  and CTR_DRBG over AES, after Bouncy Castle's `HMacSP800Drbg`,
  `HashSP800Drbg` and `CtrSP800Drbg`, checked against NIST CAVP vectors.
  `CtrDrbg` also offers the mode without the derivation function, which
  Bouncy Castle does not.
- `Drbg`, with `generate` and `reseed`, and `DrbgError`.
- `rand_core::TryRng` and `rand_core::TryCryptoRng` for every generator, with
  `DrbgError` as the error.

### Compatibility

- No allocator: the state is inline, and each seeding buffers at most 256
  bytes of entropy; a larger entropy size is `DrbgError::ExcessiveEntropy`.
- Requests over 32 KiB and requests after 2^47 since the last seeding fail
  with `DrbgError::RequestTooLarge` and `DrbgError::ReseedRequired`, through
  `rand_core` as well; nothing panics. The generators hold no entropy source
  and never reseed on their own.
- There is no `prediction_resistant` flag; call `reseed` before `generate`.
- `CtrDrbg` takes AES only; Bouncy Castle's `CtrSP800Drbg` also takes
  Triple DES.
- Depends on `rand_core` 0.10 without default features.
