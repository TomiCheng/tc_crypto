use core::fmt::{Display, Formatter};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit};
use tc_zeroize::{Zeroize, Zeroizing};

use super::shared;
use crate::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};

/// A buffering layer over the asymmetric block cipher `C` with an inline
/// buffer of `N` bytes, for builds without an allocator; Bouncy Castle's
/// `BufferedAsymmetricBlockCipher`.
///
/// An asymmetric cipher transforms one block per message, so the adapter
/// writes nothing until `do_final`, which passes everything buffered to the
/// cipher at once. `C` may be a raw engine or an encoding over one, such as
/// PKCS#1 v1.5 or OAEP over RSA; the adapter itself adds no padding.
///
/// `N` is an upper bound, not a block size: `init` fails with
/// `BufferTooSmall` when the cipher's input block under the given key, plus
/// one byte when encrypting, exceeds it. 256 bytes hold either direction of a
/// 2048-bit RSA key and 512 of a 4096-bit one.
///
/// Constant time exactly when the cipher is: the buffering branches and copies
/// only on lengths, which are public. The buffer is wiped after `do_final`, on
/// reset and on drop.
///
/// # Example
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_asym_encoding::Pkcs1Encoding;
/// use tc_buffered_cipher::{
///     BufferedCipher, BufferedCipherInit, CipherDirection, FixedBufferedAsymmetricBlockCipher,
/// };
/// use tc_rsa::{RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
///
/// // A 2048-bit key pair, whose modulus is 256 bytes.
/// let mut generator = RsaKeyGenerator::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // PKCS#1 v1.5 over RSA, behind a 256-byte buffer that fits either direction.
/// let encoding = Pkcs1Encoding::from_parts(RsaEngine::new(), rand::rng());
/// let mut cipher = FixedBufferedAsymmetricBlockCipher::<_, 256>::new(encoding);
///
/// cipher.init(CipherDirection::Encrypt, &public)?;
/// let mut sealed = vec![0; cipher.output_len(0)?];
/// cipher.process_bytes(b"attack ", &mut sealed)?; // 0: input is only buffered
/// cipher.process_bytes(b"at dawn", &mut sealed)?; // 0
/// let written = cipher.do_final(&mut sealed)?; // 256: one block of the modulus
///
/// cipher.init(CipherDirection::Decrypt, &private)?;
/// let mut opened = vec![0; cipher.output_len(written)?];
/// cipher.process_bytes(&sealed[..written], &mut opened)?;
/// let read = cipher.do_final(&mut opened)?;
/// assert_eq!(&opened[..read], b"attack at dawn");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedBufferedAsymmetricBlockCipher<C, const N: usize> {
    cipher: C,
    buffer: Zeroizing<[u8; N]>,
    capacity: usize,
    buffered: usize,
    initialized: bool,
}

impl<C, const N: usize> FixedBufferedAsymmetricBlockCipher<C, N> {
    /// Wraps `cipher` behind an inline buffer of `N` bytes; call `init` before
    /// use. Constant time.
    pub fn new(cipher: C) -> Self {
        Self {
            cipher,
            buffer: Zeroizing::new([0; N]),
            capacity: 0,
            buffered: 0,
            initialized: false,
        }
    }

    /// Returns the wrapped cipher. Constant time.
    pub const fn underlying_cipher(&self) -> &C {
        &self.cipher
    }

    fn reset_state(&mut self) {
        self.buffer.zeroize();
        self.buffered = 0;
    }
}

impl<C: Display, const N: usize> Display for FixedBufferedAsymmetricBlockCipher<C, N> {
    /// Writes the cipher's name, such as `"RSA/PKCS1Padding"`. Constant time.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.cipher.fmt(f)
    }
}

impl<C, const N: usize> BufferedCipher for FixedBufferedAsymmetricBlockCipher<C, N>
where
    C: AsymmetricBlockCipher,
    C::Error: core::error::Error + 'static,
{
    type Error = BufferedError<C::Error>;

    /// Returns the cipher's input block size, as Bouncy Castle does.
    /// Constant time: the size depends only on the key's public length.
    fn block_size(&self) -> usize {
        self.cipher.input_block_size()
    }

    /// Returns zero: input is only buffered until `do_final`. Constant time.
    fn update_output_len(&self, _input_len: usize) -> Result<usize, Self::Error> {
        Ok(0)
    }

    /// Returns the cipher's output block size, whatever `input_len` is: the
    /// most one block can write. Constant time: the size depends only on the
    /// key's public length.
    fn output_len(&self, _input_len: usize) -> Result<usize, Self::Error> {
        Ok(self.cipher.output_block_size())
    }

    /// Buffers `input`, writes nothing and returns zero; fails with
    /// `InputTooLong`, keeping what was buffered, when the message would
    /// outgrow one block. Constant time: it copies and reads only lengths.
    fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.initialized {
            return Err(BufferedError::NotInitialized);
        }
        shared::process_bytes(&mut self.buffer[..self.capacity], &mut self.buffered, input)
    }

    /// Passes the buffered message to the cipher as one block and returns the
    /// bytes it writes; an empty message writes nothing, as in Bouncy Castle.
    /// The buffer is wiped whether or not it succeeds, and the key stays for
    /// the next message. Constant time exactly when the cipher is.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let result = if self.initialized {
            shared::do_final(&mut self.cipher, &self.buffer[..self.buffered], output)
        } else {
            Err(BufferedError::NotInitialized)
        };

        self.reset_state();
        result
    }

    /// Discards the buffered input and wipes the buffer. Constant time.
    fn reset(&mut self) {
        self.reset_state();
    }
}

impl<C, P, const N: usize> BufferedCipherInit<P> for FixedBufferedAsymmetricBlockCipher<C, N>
where
    C: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    <C as AsymmetricBlockCipherInit<P>>::Error: 'static,
    P: ?Sized,
{
    type Error = BufferedError<<C as AsymmetricBlockCipherInit<P>>::Error>;

    /// Initializes the cipher in `direction` with `params` and discards any
    /// buffered input. Fails with the cipher's error, or with `BufferTooSmall`
    /// when `N` cannot hold the cipher's input block, plus one byte when
    /// encrypting; a failed `init` leaves the adapter uninitialized.
    /// Constant time exactly when the cipher's initialization is.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.initialized = false;
        self.reset_state();
        self.cipher
            .init(direction.into(), params)
            .map_err(BufferedError::Cipher)?;
        let required = shared::capacity(&self.cipher, direction);
        if required > N {
            return Err(BufferedError::BufferTooSmall {
                required,
                available: N,
            });
        }
        self.capacity = required;
        self.initialized = true;
        Ok(())
    }
}
