//! Cipher text stealing, ported from Bouncy Castle's `CtsBlockCipher`: ECB or CBC over a
//! message of any length of at least one block, with a ciphertext as long as the plaintext. It
//! implements the traits of `tc_buffered_cipher` and holds a block cipher of `tc_block_cipher`
//! itself.
//!
//! [`FixedCtsBlockCipher`] keeps its buffers inline; the `alloc` feature adds `CtsBlockCipher`,
//! which sizes them from the block size at run time. [`Ecb`] or [`Cbc`] picks the chaining.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod chaining;
#[cfg(feature = "alloc")]
mod cts_block_cipher;
mod fixed_cts_block_cipher;
mod shared;

pub use chaining::{Cbc, CtsChaining, Ecb};
#[cfg(feature = "alloc")]
pub use cts_block_cipher::CtsBlockCipher;
pub use fixed_cts_block_cipher::FixedCtsBlockCipher;
