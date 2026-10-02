use core::fmt::{Display, Formatter};
use tc_aead_cipher::{AeadBlockCipher, AeadCipherInit};

use crate::{BufferedCipher, BufferedCipherInit, CipherDirection};

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
    pub const fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: Display> Display for BufferedAeadBlockCipher<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)
    }
}

impl<C: AeadBlockCipher> BufferedCipher for BufferedAeadBlockCipher<C> {
    type Error = C::Error;

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.cipher.update_output_len(input_len)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.cipher.output_len(input_len)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.process_bytes(input, output)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.do_final(output)
    }

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

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.cipher.init(direction.into(), params)
    }
}
