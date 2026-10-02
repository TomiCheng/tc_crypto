use core::fmt::{Display, Formatter};
use tc_stream_cipher::{StreamCipher, StreamCipherInit};

use crate::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

/// Puts the stream cipher `C` behind the `BufferedCipher` interface; Bouncy
/// Castle's `BufferedStreamCipher`.
///
/// A stream cipher holds nothing back, so every call writes as much as it
/// reads, the block size is zero, and `do_final` writes nothing and restarts
/// the keystream.
///
/// Constant time exactly when the engine is: the adapter checks only public
/// lengths before passing each call on.
///
/// # Example
///
/// ```
/// use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedStreamCipher, CipherDirection};
/// use tc_chacha::ChaCha7539Engine;
/// use tc_stream_cipher::KeyWithIvRef;
///
/// let (key, nonce) = ([0x42; 32], [0x24; 12]);
/// let params = KeyWithIvRef::new(&key, &nonce);
/// let message = [0x11; 40];
///
/// // A stream cipher holds nothing back: every call writes as much as it reads.
/// let mut cipher = BufferedStreamCipher::new(ChaCha7539Engine::new());
///
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(message.len())?];
/// let mut written = cipher.process_bytes(&message[..5], &mut sealed)?; // 5
/// written += cipher.process_bytes(&message[5..], &mut sealed[written..])?; // 35
/// written += cipher.do_final(&mut sealed[written..])?; // 0, and the keystream restarts
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(written)?];
/// let mut read = cipher.process_bytes(&sealed[..written], &mut opened)?;
/// read += cipher.do_final(&mut opened[read..])?;
/// assert_eq!(opened[..read], message);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct BufferedStreamCipher<C> {
    cipher: C,
    initialized: bool,
}

impl<C> BufferedStreamCipher<C> {
    /// Wraps `cipher`; call `init` before use. Constant time.
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            initialized: false,
        }
    }

    /// Returns the wrapped stream cipher. Constant time.
    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: Display> Display for BufferedStreamCipher<C> {
    /// Writes the engine's name, such as `"ChaCha7539"`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)
    }
}

impl<C> BufferedCipher for BufferedStreamCipher<C>
where
    C: StreamCipher,
    C::Error: core::error::Error + 'static,
{
    type Error = BufferedError<C::Error>;

    /// Returns zero, as for every stream cipher. Constant time.
    fn block_size(&self) -> usize {
        0
    }

    /// Returns `input_len`: a stream cipher writes as much as it reads.
    /// Constant time.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        Ok(input_len)
    }

    /// Returns `input_len`: a stream cipher writes as much as it reads.
    /// Constant time.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        Ok(input_len)
    }

    /// Transforms one byte through the engine's `return_byte`. Constant time
    /// exactly when the engine is.
    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(BufferedError::NotInitialized);
        }
        let Some(slot) = output.first_mut() else {
            return Err(BufferedError::OutputTooShort {
                required: 1,
                available: 0,
            });
        };
        *slot = self
            .cipher
            .return_byte(input)
            .map_err(BufferedError::Cipher)?;
        Ok(1)
    }

    /// Transforms `input` into `output` through the engine and returns its
    /// length. Constant time exactly when the engine is.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(BufferedError::NotInitialized);
        }
        if output.len() < input.len() {
            return Err(BufferedError::OutputTooShort {
                required: input.len(),
                available: output.len(),
            });
        }
        self.cipher
            .process_bytes(input, output)
            .map_err(BufferedError::Cipher)
    }

    /// Writes nothing and restarts the keystream, as `reset` does.
    /// Constant time exactly when the engine's reset is.
    fn do_final(&mut self, _output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(BufferedError::NotInitialized);
        }
        self.cipher.reset();
        Ok(0)
    }

    /// Restarts the keystream from where the last `init` set it. Constant time
    /// exactly when the engine's reset is.
    fn reset(&mut self) {
        self.cipher.reset();
    }
}

impl<C, P> BufferedCipherInit<P> for BufferedStreamCipher<C>
where
    C: StreamCipherInit<P>,
    P: ?Sized,
{
    type Error = <C as StreamCipherInit<P>>::Error;

    /// Initializes the engine in `direction` with `params`; a failed `init`
    /// leaves the adapter uninitialized. Constant time exactly when the
    /// engine's initialization is.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.cipher.init(direction.into(), params)?;
        self.initialized = true;
        Ok(())
    }
}
