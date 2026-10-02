use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockCipherMode, EcbBlockCipher};
use tc_block_padding::{BlockCipherPadding, Pkcs7Padding};
use tc_zeroize::{Zeroize, Zeroizing};

use super::shared;
use crate::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

pub struct PaddedBufferedBlockCipher<C, P = Pkcs7Padding> {
    cipher_mode: C,
    padding: P,
    buffer: Zeroizing<Vec<u8>>,
    scratch: Zeroizing<Vec<u8>>,
    buffered: usize,
    encrypting: bool,
    initialized: bool,
}

impl<C: BlockCipherMode, P> PaddedBufferedBlockCipher<C, P> {
    pub fn with_padding(cipher_mode: C, padding: P) -> Self {
        let block_size = cipher_mode.block_size();
        assert!(
            block_size > 0,
            "buffered cipher requires a positive block size"
        );

        Self {
            cipher_mode,
            padding,
            buffer: Zeroizing::new(vec![0; block_size]),
            scratch: Zeroizing::new(vec![0; block_size]),
            buffered: 0,
            encrypting: false,
            initialized: false,
        }
    }

    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher_mode
    }

    pub const fn padding(&self) -> &P {
        &self.padding
    }

    fn reset_state(&mut self) {
        self.buffer[..].zeroize();
        self.scratch[..].zeroize();
        self.buffered = 0;
        self.cipher_mode.reset();
    }
}

impl<C: BlockCipher, P> PaddedBufferedBlockCipher<EcbBlockCipher<C>, P> {
    pub fn from_cipher_with_padding(cipher: C, padding: P) -> Self {
        Self::with_padding(EcbBlockCipher::new(cipher), padding)
    }
}

impl<C: BlockCipherMode> PaddedBufferedBlockCipher<C> {
    pub fn new(cipher_mode: C) -> Self {
        Self::with_padding(cipher_mode, Pkcs7Padding::new())
    }
}

impl<C: BlockCipher> PaddedBufferedBlockCipher<EcbBlockCipher<C>> {
    pub fn from_cipher(cipher: C) -> Self {
        Self::new(EcbBlockCipher::new(cipher))
    }
}

impl<C: Display, P> Display for PaddedBufferedBlockCipher<C, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher_mode.fmt(f)
    }
}

impl<C, P> BufferedCipher for PaddedBufferedBlockCipher<C, P>
where
    C: BlockCipherMode,
    C::Error: core::error::Error + 'static,
    P: BlockCipherPadding,
{
    type Error = BufferedError<C::Error>;

    fn block_size(&self) -> usize {
        self.buffer.len()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, self.buffer.len(), input_len, true)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::padded_output_len(self.buffered, self.buffer.len(), input_len, self.encrypting)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(BufferedError::NotInitialized);
        }
        shared::process_bytes(
            &mut self.cipher_mode,
            &mut self.buffer[..],
            &mut self.buffered,
            input,
            output,
            true,
        )
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let result = if self.initialized {
            shared::padded_do_final(
                &mut self.cipher_mode,
                &mut self.padding,
                &mut self.buffer[..],
                &mut self.scratch[..],
                self.buffered,
                self.encrypting,
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

impl<C, P, Q> BufferedCipherInit<Q> for PaddedBufferedBlockCipher<C, P>
where
    C: BlockCipherMode + BlockCipherInit<Q>,
    Q: ?Sized,
{
    type Error = <C as BlockCipherInit<Q>>::Error;

    fn init(&mut self, direction: CipherDirection, params: &Q) -> Result<(), Self::Error> {
        self.initialized = false;
        self.reset_state();
        self.cipher_mode.init(direction.into(), params)?;
        self.encrypting = direction == CipherDirection::Encrypt;
        self.initialized = true;
        Ok(())
    }
}
