use crate::shared::{self, Buffers};
use crate::{Cbc, CtsChaining, Ecb};
use core::marker::PhantomData;
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockModeInitError, IvParams};
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
use tc_zeroize::{Zeroize, Zeroizing};

/// Bouncy Castle's `CtsBlockCipher` over blocks of `N` bytes, with its buffers inline and no
/// allocator: the ciphertext is as long as the plaintext, and the last block may be partial,
/// but the message needs at least one whole block. `M` is the chaining, [`Ecb`] or [`Cbc`].
///
/// It chains CBC itself and holds the block cipher directly, as one of the last two blocks of
/// CTS bypasses the chaining and goes to the block cipher alone. Constant time exactly when the
/// block cipher is: it branches only on lengths, and copies. The buffers are wiped on reset and
/// on drop.
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};
/// use tc_cts_modes::{Cbc, FixedCtsBlockCipher};
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let message = b"twenty-one bytes long";
///
/// // AES-CBC with cipher text stealing: 21 bytes of plaintext give 21 bytes of ciphertext.
/// let mut cipher = FixedCtsBlockCipher::<_, 16, Cbc>::cbc(AesEngine::new());
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(message.len())?];
/// let mut written = cipher.process_bytes(message, &mut sealed)?;
/// written += cipher.do_final(&mut sealed[written..])?;
/// assert_eq!(written, message.len());
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(written)?];
/// let mut read = cipher.process_bytes(&sealed, &mut opened)?;
/// read += cipher.do_final(&mut opened[read..])?;
/// assert_eq!(&opened[..read], message);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedCtsBlockCipher<C, const N: usize, M> {
    cipher: C,
    buffer: Zeroizing<[[u8; N]; 2]>,
    chain: Zeroizing<[u8; N]>,
    next: Zeroizing<[u8; N]>,
    block: Zeroizing<[u8; N]>,
    iv: Zeroizing<[u8; N]>,
    buffered: usize,
    direction: Option<CipherDirection>,
    chaining: PhantomData<M>,
}

impl<C, const N: usize, M> FixedCtsBlockCipher<C, N, M> {
    /// Wraps `cipher`, not yet initialised. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is positive and equal to the block size of `cipher`.
    fn new(cipher: C) -> Self
    where
        C: BlockCipher,
    {
        assert!(
            N > 0 && cipher.block_size() == N,
            "fixed CTS cipher requires a positive block size equal to N"
        );
        Self {
            cipher,
            buffer: Zeroizing::new([[0; N]; 2]),
            chain: Zeroizing::new([0; N]),
            next: Zeroizing::new([0; N]),
            block: Zeroizing::new([0; N]),
            iv: Zeroizing::new([0; N]),
            buffered: 0,
            direction: None,
            chaining: PhantomData,
        }
    }

    /// Wipes the buffers and returns the chaining to the IV. Constant time.
    fn reset_state(&mut self) {
        self.buffer.zeroize();
        self.next.zeroize();
        self.block.zeroize();
        self.chain.copy_from_slice(&self.iv[..]);
        self.buffered = 0;
    }

    /// Lends the buffers the shared logic works on. Constant time.
    fn buffers(&mut self) -> (&mut C, Buffers<'_>) {
        (
            &mut self.cipher,
            Buffers {
                buffer: self.buffer.as_flattened_mut(),
                chain: &mut self.chain[..],
                next: &mut self.next[..],
                block: &mut self.block[..],
            },
        )
    }
}

impl<C: BlockCipher, const N: usize> FixedCtsBlockCipher<C, N, Ecb> {
    /// CTS without chaining, as Bouncy Castle's `CtsBlockCipher(IBlockCipher)`. Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is positive and equal to the block size of `cipher`, as the `Fixed`
    /// adapters of `tc_buffered_cipher` do.
    pub fn ecb(cipher: C) -> Self {
        Self::new(cipher)
    }
}

impl<C: BlockCipher, const N: usize> FixedCtsBlockCipher<C, N, Cbc> {
    /// CTS over CBC, as Bouncy Castle's `CtsBlockCipher(new CbcBlockCipher(cipher))`.
    /// Constant time.
    ///
    /// # Panics
    ///
    /// Panics unless `N` is positive and equal to the block size of `cipher`, as the `Fixed`
    /// adapters of `tc_buffered_cipher` do.
    pub fn cbc(cipher: C) -> Self {
        Self::new(cipher)
    }
}

impl<C, const N: usize, M> BufferedCipher for FixedCtsBlockCipher<C, N, M>
where
    C: BlockCipher,
    C::Error: core::error::Error + 'static,
    M: CtsChaining,
{
    type Error = BufferedError<C::Error>;

    /// Returns `N`. Constant time.
    fn block_size(&self) -> usize {
        N
    }

    /// The bytes this `process_bytes` writes: more than one and at most two blocks stay
    /// buffered, and the rest is written. Constant time: reads only lengths.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, N, input_len)
    }

    /// The bytes `process_bytes` and then `do_final` write, as many as the input.
    /// Constant time: reads only lengths.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::output_len(self.buffered, input_len)
    }

    /// Buffers `input` and writes what no longer belongs to the last two blocks. Constant time
    /// exactly when the block cipher is.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BufferedError::NotInitialized)?;
        let mut buffered = self.buffered;
        let (cipher, buffers) = self.buffers();
        let result = shared::process_bytes(
            cipher,
            M::CBC,
            direction == CipherDirection::Encrypt,
            buffers,
            &mut buffered,
            input,
            output,
        );
        self.buffered = buffered;
        result
    }

    /// Processes the last two blocks with cipher text stealing; `IncompleteLastBlock` with less
    /// than one whole block. Wipes the buffers and returns to the IV whether it succeeds or not.
    /// Constant time exactly when the block cipher is.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let result = match self.direction {
            Some(direction) => {
                let buffered = self.buffered;
                let (cipher, buffers) = self.buffers();
                shared::do_final(
                    cipher,
                    M::CBC,
                    direction == CipherDirection::Encrypt,
                    buffers,
                    buffered,
                    output,
                )
            }
            None => Err(BufferedError::NotInitialized),
        };
        self.reset_state();
        result
    }

    /// Drops and wipes the buffered input, and returns the chaining to the IV. Constant time.
    fn reset(&mut self) {
        self.reset_state();
    }
}

impl<C, P, const N: usize> BufferedCipherInit<P> for FixedCtsBlockCipher<C, N, Ecb>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Initialises the block cipher with `params`; on failure it stays uninitialised.
    /// Constant time exactly when the block cipher's `init` is.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        self.reset_state();
        self.cipher
            .init(direction.into(), params)
            .map_err(BlockModeInitError::Cipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}

impl<C, P, const N: usize> BufferedCipherInit<P> for FixedCtsBlockCipher<C, N, Cbc>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Checks the length of the IV, exactly `N` bytes, initialises the block cipher with
    /// `params` and loads the IV; on failure it stays uninitialised. Constant time exactly when
    /// the block cipher's `init` is: it checks only public lengths and copies the IV.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        let iv = params.iv();
        if iv.len() != N {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }
        self.iv.copy_from_slice(iv);
        self.reset_state();
        self.cipher
            .init(direction.into(), params)
            .map_err(BlockModeInitError::Cipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}
