//! NIST SP 800-90A deterministic random bit generators, after Bouncy Castle's
//! `HMacSP800Drbg`, `HashSP800Drbg` and `CtrSP800Drbg`: [`HmacDrbg`] over any
//! `tc_macs` MAC, [`HashDrbg`] over any `tc_digest` digest and [`CtrDrbg`] over
//! AES. Every one keeps its state inline and needs no allocator.
//!
//! The crate never reads the operating system's entropy itself: the caller
//! passes a `rand_core::CryptoRng` when instantiating and when reseeding, and
//! each seeding reads at most 256 bytes of entropy from it. There is no
//! `prediction_resistant` flag; for prediction resistance, call
//! [`Drbg::reseed`] before [`Drbg::generate`].
//!
//! Every generator also implements `rand_core::TryRng<Error = DrbgError>` and
//! `rand_core::TryCryptoRng`, failing as [`Drbg::generate`] does: a request
//! over 32 KiB returns [`DrbgError::RequestTooLarge`], and after 2^47 requests
//! [`DrbgError::ReseedRequired`] until the caller calls [`Drbg::reseed`]; the
//! crate holds no entropy source and never reseeds on its own. Both limits are
//! Bouncy Castle's, and neither panics. Where a `CryptoRng` is required, wrap
//! the generator in `rand_core::UnwrapErr`, which turns the errors into
//! panics.
//!
//! Each generator is constant time with respect to its state, its entropy and
//! its output exactly when its MAC, digest or block cipher is: it branches and
//! loops only on lengths and the request count. The state is wiped on drop,
//! and the temporary copies of entropy and derived values are wiped as they
//! go out of scope.
//!
//! # Example
//!
//! ```
//! use rand_core::{Rng, TryRng, UnwrapErr};
//! use tc_aes::AesEngine;
//! use tc_drbg::{CtrDrbg, Drbg, HashDrbg, HmacDrbg};
//! use tc_macs::Hmac;
//! use tc_sha::Sha256Digest;
//!
//! // The caller supplies the entropy; here it is the operating system's.
//! let mut entropy = rand::rng();
//!
//! // HMAC_DRBG: a strength of 256 bits, 32 bytes of entropy per seeding,
//! // then a nonce and a personalization string.
//! let mut drbg = HmacDrbg::new(
//!     Hmac::new(Sha256Digest::new()),
//!     256,
//!     32,
//!     &mut entropy,
//!     b"a 16-byte nonce!",
//!     b"my app v1",
//! )?;
//!
//! let mut key = [0_u8; 32];
//! drbg.generate(&mut key, &[])?;
//!
//! // For prediction resistance, reseed first; additional input may be mixed in.
//! drbg.reseed(&mut entropy, &[])?;
//! drbg.generate(&mut key, b"additional input")?;
//!
//! // As a rand_core source, errors are returned...
//! let _ = drbg.try_next_u64()?;
//!
//! // ...and UnwrapErr turns them into panics where a CryptoRng is required.
//! let _ = UnwrapErr(&mut drbg).next_u64();
//!
//! // Hash_DRBG and CTR_DRBG are made the same way over other primitives.
//! let mut hash = HashDrbg::new(Sha256Digest::new(), 256, 32, &mut entropy, b"nonce", &[])?;
//! hash.generate(&mut key, &[])?;
//!
//! // CTR_DRBG also takes the AES key size in bits.
//! let mut ctr = CtrDrbg::new_with_derivation_function(
//!     AesEngine::new(),
//!     256,
//!     256,
//!     32,
//!     &mut entropy,
//!     b"nonce",
//!     &[],
//! )?;
//! ctr.generate(&mut key, &[])?;
//! # Ok::<(), tc_drbg::DrbgError>(())
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod ctr_drbg;
mod derivation;
mod drbg;
mod errors;
mod hash_drbg;
mod hmac_drbg;
mod traits;

pub use ctr_drbg::CtrDrbg;
pub use errors::DrbgError;
pub use hash_drbg::HashDrbg;
pub use hmac_drbg::HmacDrbg;
pub use traits::Drbg;
