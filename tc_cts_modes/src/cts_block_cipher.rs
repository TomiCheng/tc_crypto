use crate::shared::{self, Buffers};
use crate::{Cbc, CtsChaining, Ecb};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockModeInitError, IvParams};
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
use tc_zeroize::{Zeroize, Zeroizing};

/// As [`FixedCtsBlockCipher`](crate::FixedCtsBlockCipher), with the buffers sized in `init` from
/// the block size of the block cipher, for callers that learn the block size only at run time,
/// such as a factory. Needs the `alloc` feature.
///
/// Constant time exactly when the block cipher is: it branches only on lengths, and copies. The
/// buffers are wiped on reset, when sized again, and on drop.
pub struct CtsBlockCipher<C, M> {
    cipher: C,
    buffer: Zeroizing<Vec<u8>>,
    chain: Zeroizing<Vec<u8>>,
    next: Zeroizing<Vec<u8>>,
    block: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
    buffered: usize,
    direction: Option<CipherDirection>,
    chaining: PhantomData<M>,
}

impl<C, M> CtsBlockCipher<C, M> {
    /// Wraps `cipher`, not yet initialised and with no buffers yet. Constant time.
    fn new(cipher: C) -> Self {
        Self {
            cipher,
            buffer: Zeroizing::new(Vec::new()),
            chain: Zeroizing::new(Vec::new()),
            next: Zeroizing::new(Vec::new()),
            block: Zeroizing::new(Vec::new()),
            iv: Zeroizing::new(Vec::new()),
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
        self.chain.copy_from_slice(&self.iv);
        self.buffered = 0;
    }

    /// Sizes the buffers again for a block of `n` bytes; the old ones are wiped as they drop.
    /// Constant time: depends only on lengths.
    fn allocate(&mut self, n: usize, iv: &[u8]) {
        self.buffer = Zeroizing::new(vec![0; 2 * n]);
        self.chain = Zeroizing::new(iv.to_vec());
        self.next = Zeroizing::new(vec![0; n]);
        self.block = Zeroizing::new(vec![0; n]);
        self.iv = Zeroizing::new(iv.to_vec());
        self.buffered = 0;
    }

    /// Lends the buffers the shared logic works on. Constant time.
    fn buffers(&mut self) -> (&mut C, Buffers<'_>) {
        (
            &mut self.cipher,
            Buffers {
                buffer: &mut self.buffer,
                chain: &mut self.chain,
                next: &mut self.next,
                block: &mut self.block,
            },
        )
    }
}

impl<C> CtsBlockCipher<C, Ecb> {
    /// CTS without chaining, as Bouncy Castle's `CtsBlockCipher(IBlockCipher)`. Constant time.
    pub fn ecb(cipher: C) -> Self {
        Self::new(cipher)
    }
}

impl<C> CtsBlockCipher<C, Cbc> {
    /// CTS over CBC, as Bouncy Castle's `CtsBlockCipher(new CbcBlockCipher(cipher))`.
    /// Constant time.
    pub fn cbc(cipher: C) -> Self {
        Self::new(cipher)
    }
}

impl<C, M> BufferedCipher for CtsBlockCipher<C, M>
where
    C: BlockCipher,
    C::Error: core::error::Error + 'static,
    M: CtsChaining,
{
    type Error = BufferedError<C::Error>;

    /// The block size of the block cipher. Constant time.
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    /// The bytes this `process_bytes` writes: more than one and at most two blocks stay
    /// buffered, and the rest is written. Constant time: reads only lengths.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, self.chain.len(), input_len)
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

impl<C, P> BufferedCipherInit<P> for CtsBlockCipher<C, Ecb>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Initialises the block cipher with `params` and sizes the buffers from its block size; on
    /// failure it stays uninitialised. Constant time exactly when the block cipher's `init` is.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        self.cipher
            .init(direction.into(), params)
            .map_err(BlockModeInitError::Cipher)?;
        let n = self.cipher.block_size();
        self.allocate(n, &vec![0; n]);
        self.direction = Some(direction);
        Ok(())
    }
}

impl<C, P> BufferedCipherInit<P> for CtsBlockCipher<C, Cbc>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// Initialises the block cipher with `params`, whose IV must be exactly one block, sizes the
    /// buffers from the block size and loads the IV; on failure it stays uninitialised.
    /// Constant time exactly when the block cipher's `init` is: it checks only public lengths and copies
    /// the IV.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        self.cipher
            .init(direction.into(), params)
            .map_err(BlockModeInitError::Cipher)?;
        let n = self.cipher.block_size();
        let iv = params.iv();
        if iv.len() != n {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }
        self.allocate(n, iv);
        self.direction = Some(direction);
        Ok(())
    }
}
