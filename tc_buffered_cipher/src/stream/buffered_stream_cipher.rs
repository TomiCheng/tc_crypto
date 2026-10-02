use core::fmt::{Display, Formatter};
use tc_stream_cipher::{StreamCipher, StreamCipherInit};

use crate::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

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
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            initialized: false,
        }
    }

    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: Display> Display for BufferedStreamCipher<C> {
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

    fn block_size(&self) -> usize {
        0
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        Ok(input_len)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        Ok(input_len)
    }

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

    fn do_final(&mut self, _output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(BufferedError::NotInitialized);
        }
        self.cipher.reset();
        Ok(0)
    }

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

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.cipher.init(direction.into(), params)?;
        self.initialized = true;
        Ok(())
    }
}
