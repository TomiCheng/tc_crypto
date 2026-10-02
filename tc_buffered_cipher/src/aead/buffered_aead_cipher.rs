use core::fmt::{Display, Formatter};
use tc_aead_cipher::{AeadCipher, AeadCipherInit};

use crate::{BufferedCipher, BufferedCipherInit, CipherDirection};

/// Puts the AEAD `C` behind the `BufferedCipher` interface, for an algorithm
/// that carries its own primitive, such as Ascon; Bouncy Castle's
/// `BufferedAeadCipher`. Modes over a block cipher belong in
/// `BufferedAeadBlockCipher`, which reports that cipher's block size.
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
/// use tc_aead_cipher::AeadParamsRef;
/// use tc_ascon_aead::AsconAead128Engine;
/// use tc_buffered_cipher::{BufferedAeadCipher, BufferedCipher, BufferedCipherInit, CipherDirection};
///
/// let (key, nonce) = ([0x42; 16], [0x24; 16]);
/// // The associated data rides in the parameters; the interface has no method for it.
/// let params = AeadParamsRef::new(&key, &nonce, 16, b"header");
/// let message = [0x11; 40];
///
/// // Ascon carries its own permutation, so there is no block cipher to report.
/// let mut cipher = BufferedAeadCipher::new(AsconAead128Engine::new());
/// assert_eq!(cipher.block_size(), 0);
///
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(message.len())?]; // 56: 40 bytes and a 16-byte tag
/// let mut written = cipher.process_bytes(&message[..5], &mut sealed)?;
/// written += cipher.process_bytes(&message[5..], &mut sealed[written..])?;
/// written += cipher.do_final(&mut sealed[written..])?; // the rest and the tag
/// # assert_eq!((sealed.len(), written), (56, 56));
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(written)?];
/// let mut read = cipher.process_bytes(&sealed[..written], &mut opened)?;
/// read += cipher.do_final(&mut opened[read..])?; // fails if the tag does not match
/// assert_eq!(opened[..read], message);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct BufferedAeadCipher<C> {
    cipher: C,
}

impl<C> BufferedAeadCipher<C> {
    /// Wraps `cipher`; call `init` before use. Constant time.
    pub const fn new(cipher: C) -> Self {
        Self { cipher }
    }

    /// Returns the wrapped AEAD engine. Constant time.
    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: Display> Display for BufferedAeadCipher<C> {
    /// Writes the engine's name, such as `"Ascon-AEAD128"`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)
    }
}

impl<C: AeadCipher> BufferedCipher for BufferedAeadCipher<C> {
    type Error = C::Error;

    /// Returns zero: an AEAD that carries its own primitive has no block cipher
    /// to report. Constant time.
    fn block_size(&self) -> usize {
        0
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

impl<C, P> BufferedCipherInit<P> for BufferedAeadCipher<C>
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
