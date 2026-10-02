use core::fmt::{Display, Formatter};
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockCipherMode, EcbBlockCipher};
use tc_block_padding::{BlockCipherPadding, Pkcs7Padding};
use tc_zeroize::{Zeroize, Zeroizing};

use super::shared;
use crate::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

/// A buffering layer over the block-cipher mode `C` with blocks of `N` bytes
/// that pads the final block with `P`, PKCS#7 unless another scheme is given,
/// and keeps its buffers inline for builds without an allocator; Bouncy
/// Castle's `PaddedBufferedBlockCipher`.
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
/// Its two blocks of buffer are wiped on reset and on drop.
///
/// # Example
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::{FixedCbcBlockCipher, KeyWithIvRef};
/// use tc_buffered_cipher::{
///     BufferedCipher, BufferedCipherInit, CipherDirection, FixedPaddedBufferedBlockCipher,
/// };
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let message = b"attack at dawn";
///
/// // AES-CBC with PKCS#7, the padding used unless another scheme is given.
/// let mode = FixedCbcBlockCipher::<_, 16>::new(AesEngine::new());
/// let mut cipher = FixedPaddedBufferedBlockCipher::<_, 16>::new(mode);
///
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(message.len())?]; // 16: up to a whole block
/// let mut written = cipher.process_bytes(message, &mut sealed)?; // 0: the final block waits
/// written += cipher.do_final(&mut sealed[written..])?; // 16: padded and encrypted
/// # assert_eq!((sealed.len(), written), (16, 16));
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(written)?]; // 16: a bound before unpadding
/// let mut read = cipher.process_bytes(&sealed[..written], &mut opened)?;
/// read += cipher.do_final(&mut opened[read..])?; // 14: the padding removed
/// # assert_eq!(read, 14);
/// assert_eq!(&opened[..read], message);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
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
    /// Buffers `cipher_mode` with `padding` in two inline blocks of `N` bytes.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is positive and equal to the mode's block size.
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

impl<C: BlockCipher, P, const N: usize> FixedPaddedBufferedBlockCipher<EcbBlockCipher<C>, N, P> {
    /// Buffers `cipher` in ECB mode with `padding`. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is positive and equal to the cipher's block size.
    pub fn from_cipher_with_padding(cipher: C, padding: P) -> Self {
        Self::with_padding(EcbBlockCipher::new(cipher), padding)
    }
}

impl<C: BlockCipherMode, const N: usize> FixedPaddedBufferedBlockCipher<C, N> {
    /// Buffers `cipher_mode` with PKCS#7 padding, as Bouncy Castle's
    /// one-argument constructor does. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is positive and equal to the mode's block size.
    pub fn new(cipher_mode: C) -> Self {
        Self::with_padding(cipher_mode, Pkcs7Padding::new())
    }
}

impl<C: BlockCipher, const N: usize> FixedPaddedBufferedBlockCipher<EcbBlockCipher<C>, N> {
    /// Buffers `cipher` in ECB mode with PKCS#7 padding. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is positive and equal to the cipher's block size.
    pub fn from_cipher(cipher: C) -> Self {
        Self::new(EcbBlockCipher::new(cipher))
    }
}

impl<C: Display, P, const N: usize> Display for FixedPaddedBufferedBlockCipher<C, N, P> {
    /// Writes the mode's name, such as `"AES/CBC"`. Constant time.
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

    /// Returns the mode's block size. Constant time.
    fn block_size(&self) -> usize {
        N
    }

    /// Returns how many bytes the next `process_bytes` writes for `input_len`
    /// more bytes: every block they complete but a final one, which is kept for
    /// `do_final`. Constant time: it reads only lengths.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, N, input_len, true)
    }

    /// Returns an upper bound for what `process_bytes` and `do_final` write
    /// together for `input_len` more bytes. Encryption rounds up to the next
    /// whole block and adds one when the input fills its last block; decryption
    /// counts the input before the padding is removed. Constant time: it reads
    /// only lengths.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::padded_output_len(self.buffered, N, input_len, self.encrypting)
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

impl<C, P, Q, const N: usize> BufferedCipherInit<Q> for FixedPaddedBufferedBlockCipher<C, N, P>
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
