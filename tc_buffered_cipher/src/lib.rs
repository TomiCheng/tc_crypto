//! One buffered interface over block modes with or without padding, stream
//! ciphers and AEADs: the [`BufferedCipher`] and [`BufferedCipherInit`]
//! contracts, the Rust form of Bouncy Castle's `IBufferedCipher`, and the
//! adapters that put each family behind them.
//!
//! - [`FixedBufferedBlockCipher`] and `BufferedBlockCipher` (`alloc`) — a
//!   `tc_block_modes` mode, buffered to whole blocks.
//! - [`FixedPaddedBufferedBlockCipher`] and `PaddedBufferedBlockCipher`
//!   (`alloc`) — the same with a `tc_block_padding` scheme, PKCS#7 by default.
//! - [`BufferedStreamCipher`] — a `tc_stream_cipher` engine.
//! - [`BufferedAeadBlockCipher`] and [`BufferedAeadCipher`] — a
//!   `tc_aead_cipher` mode over a block cipher, or an AEAD that carries its own
//!   primitive.
//!
//! Every adapter takes input in pieces of any size, holds back what its cipher
//! cannot process yet and finishes in `do_final`; the sizing methods say how
//! much each call writes. [`CipherDirection`] converts to and from the
//! block-cipher and stream-cipher contracts' own directions. [`BufferedError`]
//! carries the failures of the block and stream adapters, while the AEAD
//! adapters report their engine's error.
//!
//! The crate is `no_std` and contains no `unsafe` code. The default-off `alloc`
//! feature adds the adapters that size their buffers from the mode at run
//! time; the `Fixed` forms keep theirs inline.
//!
//! Every adapter documents its timing: each is constant time exactly when the
//! cipher it wraps is, and lengths are public. Padded decryption needs care: the
//! length it writes and a `CorruptPadding` error reveal the padding, which is a
//! padding oracle, so authenticate CBC ciphertext before decrypting it, or use
//! an AEAD.
//!
//! # Example
//!
//! Generic code drives every family through the same calls:
//!
//! ```
//! use tc_aes::AesEngine;
//! use tc_block_modes::FixedCbcBlockCipher;
//! use tc_buffered_cipher::{
//!     BufferedCipher, BufferedCipherInit, BufferedStreamCipher, CipherDirection,
//!     FixedPaddedBufferedBlockCipher,
//! };
//! use tc_chacha::ChaCha7539Engine;
//!
//! fn seal<C: BufferedCipher>(cipher: &mut C, message: &[u8]) -> Result<Vec<u8>, C::Error> {
//!     let mut sealed = vec![0; cipher.output_len(message.len())?];
//!     let mut written = cipher.process_bytes(message, &mut sealed)?;
//!     written += cipher.do_final(&mut sealed[written..])?;
//!     sealed.truncate(written);
//!     Ok(sealed)
//! }
//!
//! let message = b"attack at dawn";
//!
//! let mode = FixedCbcBlockCipher::<_, 16>::new(AesEngine::new());
//! let mut cbc = FixedPaddedBufferedBlockCipher::<_, 16>::new(mode);
//! let params = tc_block_modes::KeyWithIvRef::new(&[0x42; 16], &[0x24; 16]);
//! cbc.init(CipherDirection::Encrypt, &params)?;
//! assert_eq!(seal(&mut cbc, message)?.len(), 16); // padded to a whole block
//!
//! let mut chacha = BufferedStreamCipher::new(ChaCha7539Engine::new());
//! let params = tc_stream_cipher::KeyWithIvRef::new(&[0x42; 32], &[0x24; 12]);
//! chacha.init(CipherDirection::Encrypt, &params)?;
//! assert_eq!(seal(&mut chacha, message)?.len(), 14); // as long as the message
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod aead;
mod block;
mod cipher_direction;
mod errors;
mod stream;
mod traits;

pub use aead::BufferedAeadBlockCipher;
pub use aead::BufferedAeadCipher;
#[cfg(feature = "alloc")]
pub use block::BufferedBlockCipher;
pub use block::FixedBufferedBlockCipher;
pub use block::FixedPaddedBufferedBlockCipher;
#[cfg(feature = "alloc")]
pub use block::PaddedBufferedBlockCipher;
pub use cipher_direction::CipherDirection;
pub use errors::BufferedError;
pub use stream::BufferedStreamCipher;
pub use traits::BufferedCipher;
pub use traits::BufferedCipherInit;
