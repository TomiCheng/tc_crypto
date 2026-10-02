use core::fmt::{Display, Formatter};
use tc_aead_cipher::{AeadBlockCipher, AeadCipherInit};

use crate::{BufferedCipher, BufferedCipherInit, CipherDirection};

/// Puts the AEAD mode `C` over a block cipher, such as GCM, behind the
/// `BufferedCipher` interface; Bouncy Castle's `BufferedAeadBlockCipher`.
/// Algorithms that carry their own primitive belong in `BufferedAeadCipher`.
///
/// The engine buffers what its construction needs, so every call passes
/// straight through and the engine's errors, such as a failed tag check or a
/// refused nonce reuse, reach the caller unchanged. Associated data goes in
/// only as the initial associated data of the parameters, as in Bouncy Castle.
///
/// Constant time exactly when the engine is; the adapter adds no work of its
/// own.
///
/// # Example
///
/// ```
/// use tc_aead_cipher::{AeadParamsRef, GcmBlockCipher};
/// use tc_aes::AesEngine;
/// use tc_buffered_cipher::{
///     BufferedAeadBlockCipher, BufferedCipher, BufferedCipherInit, CipherDirection,
/// };
///
/// let (key, nonce) = ([0x42; 16], [0x24; 12]);
/// // The associated data rides in the parameters; the interface has no method for it.
/// let params = AeadParamsRef::new(&key, &nonce, 16, b"header");
/// let message = [0x11; 40];
///
/// let mut cipher = BufferedAeadBlockCipher::new(GcmBlockCipher::new(AesEngine::new()));
///
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(message.len())?]; // 56: 40 bytes and a 16-byte tag
/// let mut written = cipher.process_bytes(&message[..5], &mut sealed)?; // 0: the block is not full yet
/// # assert_eq!((sealed.len(), written), (56, 0));
/// written += cipher.process_bytes(&message[5..], &mut sealed[written..])?; // 32: two blocks
/// # assert_eq!(written, 32);
/// written += cipher.do_final(&mut sealed[written..])?; // 24: the last 8 bytes and the tag
/// # assert_eq!(written, 56);
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(written)?];
/// let mut read = cipher.process_bytes(&sealed[..written], &mut opened)?;
/// read += cipher.do_final(&mut opened[read..])?; // fails if the tag does not match
/// assert_eq!(opened[..read], message);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct BufferedAeadBlockCipher<C> {
    cipher: C,
}

impl<C> BufferedAeadBlockCipher<C> {
    /// Wraps `cipher`; call `init` before use. Constant time.
    pub const fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Returns the wrapped AEAD engine. Constant time.
    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: Display> Display for BufferedAeadBlockCipher<C> {
    /// Writes the engine's name, such as `"AES/GCM"`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)
    }
}

impl<C: AeadBlockCipher> BufferedCipher for BufferedAeadBlockCipher<C> {
    type Error = C::Error;

    /// Returns the underlying block cipher's block size. Constant time.
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    /// Returns what the engine's `update_output_len` does. Constant time
    /// exactly when the engine's is.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.cipher.update_output_len(input_len)
    }

    /// Returns what the engine's `output_len` does, the tag included.
    /// Constant time exactly when the engine's is.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.cipher.output_len(input_len)
    }

    /// Passes `input` to the engine and returns the bytes written. When
    /// decrypting, that output is not authenticated until `do_final` succeeds.
    /// Constant time exactly when the engine is.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.process_bytes(input, output)
    }

    /// Finishes the message through the engine, which appends or verifies the
    /// tag; a failed tag check releases no plaintext. Constant time exactly
    /// when the engine is.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.do_final(output)
    }

    /// Restarts the message as the engine's `reset` does. Constant time exactly
    /// when the engine's reset is.
    fn reset(&mut self) {
        self.cipher.reset();
    }
}

impl<C, P> BufferedCipherInit<P> for BufferedAeadBlockCipher<C>
where
    C: AeadCipherInit<P>,
    P: ?Sized,
{
    type Error = <C as AeadCipherInit<P>>::Error;

    /// Initializes the engine in `direction` with `params`, whose initial
    /// associated data is the only way in for associated data. Constant time
    /// exactly when the engine's initialization is.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.cipher.init(direction.into(), params)
    }
}
