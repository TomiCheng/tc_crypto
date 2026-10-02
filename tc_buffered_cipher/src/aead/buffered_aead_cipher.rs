use core::fmt::{Display, Formatter};
use tc_aead_cipher::{AeadCipher, AeadCipherInit};

use crate::{BufferedCipher, BufferedCipherInit, CipherDirection};

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
    pub const fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher
    }
}

impl<C: Display> Display for BufferedAeadCipher<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)
    }
}

impl<C: AeadCipher> BufferedCipher for BufferedAeadCipher<C> {
    type Error = C::Error;

    fn block_size(&self) -> usize {
        0
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

impl<C, P> BufferedCipherInit<P> for BufferedAeadCipher<C>
where
    C: AeadCipherInit<P>,
    P: ?Sized,
{
    type Error = <C as AeadCipherInit<P>>::Error;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.cipher.init(direction.into(), params)
    }
}
