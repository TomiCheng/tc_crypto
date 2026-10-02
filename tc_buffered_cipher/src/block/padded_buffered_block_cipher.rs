use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockCipherMode, EcbBlockCipher};
use tc_block_padding::{BlockCipherPadding, Pkcs7Padding};
use tc_zeroize::{Zeroize, Zeroizing};

use super::shared;
use crate::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

/// A buffering layer over the block-cipher mode `C` that pads the final block
/// with `P`, PKCS#7 unless another scheme is given, and sizes its buffers from
/// the mode at run time; Bouncy Castle's `PaddedBufferedBlockCipher`. Available
/// with the `alloc` feature.
///
/// A completed final block is held back until `do_final`, since on decryption
/// it carries the padding. Encryption pads the held-back bytes and, when they
/// fill the block, sends it as is and adds a block of padding alone, whatever
/// the scheme.
///
/// Encryption is constant time exactly when the mode is, since the schemes of
/// `tc_block_padding` pad in constant time. Decryption is too, apart from what
/// the padding check reveals: the length written gives the padding length, and
/// a `CorruptPadding` error whether the padding was valid. That is a padding
/// oracle. An attacker who can submit ciphertexts and observe either can
/// decrypt CBC traffic, so authenticate the ciphertext before decrypting it, or
/// use an AEAD.
///
/// Its two blocks of buffer are allocated once, never grow, and are wiped on
/// reset and on drop.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::{CbcBlockCipher, KeyWithIvRef};
/// use tc_block_padding::Iso7816d4Padding;
/// use tc_buffered_cipher::{
///     BufferedCipher, BufferedCipherInit, CipherDirection, PaddedBufferedBlockCipher,
/// };
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let message = b"attack at dawn";
///
/// // AES-CBC with PKCS#7; with_padding takes any other scheme.
/// let mut cipher = PaddedBufferedBlockCipher::new(CbcBlockCipher::new(AesEngine::new()));
/// let _iso = PaddedBufferedBlockCipher::with_padding(
///     CbcBlockCipher::new(AesEngine::new()),
///     Iso7816d4Padding::new(),
/// );
///
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(message.len())?];
/// let mut written = cipher.process_bytes(message, &mut sealed)?;
/// written += cipher.do_final(&mut sealed[written..])?;
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(written)?];
/// let mut read = cipher.process_bytes(&sealed[..written], &mut opened)?;
/// read += cipher.do_final(&mut opened[read..])?;
/// assert_eq!(&opened[..read], message);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
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
    /// Buffers `cipher_mode` with `padding`, allocating its two blocks of
    /// buffer once. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `cipher_mode` reports a block size of zero.
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

    /// Returns the wrapped mode. Constant time.
    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher_mode
    }

    /// Returns the padding scheme. Constant time.
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
    /// Buffers `cipher` in ECB mode with `padding`. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `cipher` reports a block size of zero.
    pub fn from_cipher_with_padding(cipher: C, padding: P) -> Self {
        Self::with_padding(EcbBlockCipher::new(cipher), padding)
    }
}

impl<C: BlockCipherMode> PaddedBufferedBlockCipher<C> {
    /// Buffers `cipher_mode` with PKCS#7 padding, as Bouncy Castle's
    /// one-argument constructor does. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `cipher_mode` reports a block size of zero.
    pub fn new(cipher_mode: C) -> Self {
        Self::with_padding(cipher_mode, Pkcs7Padding::new())
    }
}

impl<C: BlockCipher> PaddedBufferedBlockCipher<EcbBlockCipher<C>> {
    /// Buffers `cipher` in ECB mode with PKCS#7 padding. Constant time.
    ///
    /// # Panics
    ///
    /// Panics if `cipher` reports a block size of zero.
    pub fn from_cipher(cipher: C) -> Self {
        Self::new(EcbBlockCipher::new(cipher))
    }
}

impl<C: Display, P> Display for PaddedBufferedBlockCipher<C, P> {
    /// Writes the mode's name, such as `"AES/CBC"`. Constant time.
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

    /// Returns the mode's block size. Constant time.
    fn block_size(&self) -> usize {
        self.buffer.len()
    }

    /// Returns how many bytes the next `process_bytes` writes for `input_len`
    /// more bytes: every block they complete but a final one, which is kept for
    /// `do_final`. Constant time: it reads only lengths.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, self.buffer.len(), input_len, true)
    }

    /// Returns an upper bound for what `process_bytes` and `do_final` write
    /// together for `input_len` more bytes. Encryption rounds up to the next
    /// whole block and adds one when the input fills its last block; decryption
    /// counts the input before the padding is removed. Constant time: it reads
    /// only lengths.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::padded_output_len(self.buffered, self.buffer.len(), input_len, self.encrypting)
    }

    /// Buffers `input`, passes every block it completes but a final one to the
    /// mode and returns the bytes written. Constant time exactly when the mode
    /// is.
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

    /// Pads and encrypts the final block, followed by a block of padding alone
    /// when the input filled its last block, or decrypts it and removes the
    /// padding. The buffers are wiped and the mode reset whether or not it
    /// succeeds.
    ///
    /// Constant time exactly when the mode is, apart from what decryption's
    /// padding check reveals: the padding length through the length written,
    /// and its validity through `CorruptPadding`.
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

    /// Discards the buffered input, wipes the buffers and resets the mode.
    /// Constant time.
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

    /// Initializes the mode in `direction` with `params` and discards any
    /// buffered input; a failed `init` leaves the adapter uninitialized.
    /// Constant time exactly when the mode's initialization is.
    fn init(&mut self, direction: CipherDirection, params: &Q) -> Result<(), Self::Error> {
        self.initialized = false;
        self.reset_state();
        self.cipher_mode.init(direction.into(), params)?;
        self.encrypting = direction == CipherDirection::Encrypt;
        self.initialized = true;
        Ok(())
    }
}
