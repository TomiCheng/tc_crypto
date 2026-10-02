//! Buffered block cipher implementation.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockCipherMode, EcbBlockCipher};
use tc_zeroize::{Zeroize, Zeroizing};

use super::shared;
use crate::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

/// An unpadded buffering layer over the block-cipher mode `C`.
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::{CbcBlockCipher, KeyWithIvRef};
/// use tc_buffered_cipher::{BufferedBlockCipher, BufferedCipher, BufferedCipherInit, CipherDirection};
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let message = [0x11; 32];
///
/// // The buffer is sized from the mode at run time, so no block size appears in the type.
/// let mut cipher = BufferedBlockCipher::new(CbcBlockCipher::new(AesEngine::new()));
///
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(message.len())?];
/// let mut written = cipher.process_bytes(&message[..5], &mut sealed)?; // 0: the block is not full yet
/// written += cipher.process_bytes(&message[5..], &mut sealed[written..])?; // 32: both blocks
/// written += cipher.do_final(&mut sealed[written..])?; // 0: nothing left over
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(written)?];
/// let mut read = cipher.process_bytes(&sealed[..written], &mut opened)?;
/// read += cipher.do_final(&mut opened[read..])?;
/// assert_eq!(opened[..read], message);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct BufferedBlockCipher<C> {
    cipher_mode: C,
    buffer: Zeroizing<Vec<u8>>,
    scratch: Zeroizing<Vec<u8>>,
    buffered: usize,
    initialized: bool,
}

impl<C: BlockCipherMode> BufferedBlockCipher<C> {
    /// Wraps a block-cipher mode and allocates two blocks of buffering state.
    ///
    /// # Panics
    ///
    /// Panics if `cipher_mode` reports a block size of zero.
    pub fn new(cipher_mode: C) -> Self {
        let block_size = cipher_mode.block_size();
        assert!(
            block_size > 0,
            "buffered cipher requires a positive block size"
        );

        Self {
            cipher_mode,
            buffer: Zeroizing::new(vec![0; block_size]),
            scratch: Zeroizing::new(vec![0; block_size]),
            buffered: 0,
            initialized: false,
        }
    }

    /// Returns the wrapped block-cipher mode.
    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher_mode
    }

    fn reset_state(&mut self) {
        self.buffer[..].zeroize();
        self.scratch[..].zeroize();
        self.buffered = 0;
        self.cipher_mode.reset();
    }
}

impl<C: BlockCipher> BufferedBlockCipher<EcbBlockCipher<C>> {
    /// Wraps a bare block cipher in ECB mode and then buffers it.
    pub fn from_cipher(cipher: C) -> Self {
        Self::new(EcbBlockCipher::new(cipher))
    }
}

impl<C: Display> Display for BufferedBlockCipher<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher_mode.fmt(f)
    }
}

impl<C> BufferedCipher for BufferedBlockCipher<C>
where
    C: BlockCipherMode,
    C::Error: core::error::Error + 'static,
{
    type Error = BufferedError<C::Error>;

    fn block_size(&self) -> usize {
        self.buffer.len()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, self.buffer.len(), input_len, false)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::output_len(self.buffered, input_len)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(BufferedError::NotInitialized);
        }
        shared::process_bytes(
            &mut self.cipher_mode,
            &mut self.buffer,
            &mut self.buffered,
            input,
            output,
            false,
        )
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let result = if self.initialized {
            shared::do_final(
                &mut self.cipher_mode,
                &mut self.buffer,
                &mut self.scratch,
                self.buffered,
                output,
            )
        } else {
            Err(BufferedError::NotInitialized)
        };

        self.reset_state();
        result
    }

    fn reset(&mut self) {
        self.reset_state();
    }
}

impl<C, P> BufferedCipherInit<P> for BufferedBlockCipher<C>
where
    C: BlockCipherMode + BlockCipherInit<P>,
    P: ?Sized,
{
    type Error = <C as BlockCipherInit<P>>::Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.reset_state();
        self.cipher_mode.init(direction.into(), params)?;
        self.initialized = true;
        Ok(())
    }
}
