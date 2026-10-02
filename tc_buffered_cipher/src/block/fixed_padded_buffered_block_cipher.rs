use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockCipherMode, EcbBlockCipher};
use tc_block_padding::{BlockCipherPadding, Pkcs7Padding};
use tc_zeroize::{Zeroize, Zeroizing};

use super::shared;
use crate::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

pub struct FixedPaddedBufferedBlockCipher<C, const N: usize, P = Pkcs7Padding> {
    cipher_mode: C,
    padding: P,
    buffer: Zeroizing<[u8; N]>,
    scratch: Zeroizing<[u8; N]>,
    buffered: usize,
    encrypting: bool,
    initialized: bool,
}

impl<C: BlockCipherMode, P, const N: usize> FixedPaddedBufferedBlockCipher<C, N, P> {
    pub fn with_padding(cipher_mode: C, padding: P) -> Self {
        assert!(
            N > 0 && cipher_mode.block_size() == N,
            "fixed buffered cipher requires a positive block size equal to N"
        );

        Self {
            cipher_mode,
            padding,
            buffer: Zeroizing::new([0; N]),
            scratch: Zeroizing::new([0; N]),
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

impl<C: BlockCipher, P, const N: usize> FixedPaddedBufferedBlockCipher<EcbBlockCipher<C>, N, P> {
    pub fn from_cipher_with_padding(cipher: C, padding: P) -> Self {
        Self::with_padding(EcbBlockCipher::new(cipher), padding)
    }
}

impl<C: BlockCipherMode, const N: usize> FixedPaddedBufferedBlockCipher<C, N> {
    pub fn new(cipher_mode: C) -> Self {
        Self::with_padding(cipher_mode, Pkcs7Padding::new())
    }
}

impl<C: BlockCipher, const N: usize> FixedPaddedBufferedBlockCipher<EcbBlockCipher<C>, N> {
    pub fn from_cipher(cipher: C) -> Self {
        Self::new(EcbBlockCipher::new(cipher))
    }
}

impl<C: Display, P, const N: usize> Display for FixedPaddedBufferedBlockCipher<C, N, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher_mode.fmt(f)
    }
}

impl<C, P, const N: usize> BufferedCipher for FixedPaddedBufferedBlockCipher<C, N, P>
where
    C: BlockCipherMode,
    C::Error: core::error::Error + 'static,
    P: BlockCipherPadding,
{
    type Error = BufferedError<C::Error>;

    fn block_size(&self) -> usize {
        N
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, N, input_len, true)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::padded_output_len(self.buffered, N, input_len, self.encrypting)
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

impl<C, P, Q, const N: usize> BufferedCipherInit<Q> for FixedPaddedBufferedBlockCipher<C, N, P>
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
