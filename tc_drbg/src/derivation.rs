use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_digest::Digest;
use tc_zeroize::Zeroizing;

use crate::DrbgError;
use crate::drbg::total_len;

/// The block size of AES, the only cipher CTR_DRBG takes.
pub(crate) const AES_BLOCK_SIZE: usize = 16;

/// The largest digest or MAC output SP 800-90A supports, SHA-512's.
pub(crate) const MAX_OUTPUT_SIZE: usize = 64;

/// The longest CTR_DRBG seedlen, AES-256's key and block: 48 bytes.
pub(crate) const MAX_CTR_SEED_LEN: usize = 32 + AES_BLOCK_SIZE;

/// The block cipher derivation function's key, `0x00 0x01 ... 0x1f`.
const K_BITS: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// The highest security strength, in bits, of a digest or MAC with this
/// output size, from SP 800-57 part 1 as SP 800-90A uses it. Constant time:
/// reads only the public size.
pub(crate) fn max_hash_security_strength(output_size: usize) -> Result<usize, DrbgError> {
    match output_size {
        20 => Ok(128),
        28 => Ok(192),
        32 | 48 | 64 => Ok(256),
        _ => Err(DrbgError::UnsupportedOutputSize(output_size)),
    }
}

/// Hash_DRBG's seedlen in bits for this output size. Constant time: reads
/// only the public size.
pub(crate) const fn hash_seed_bits(output_size: usize) -> usize {
    if output_size <= 32 { 440 } else { 888 }
}

/// SP 800-90A §10.3.1 Hash_df over the concatenation of `parts`, into the
/// first `output_bits.div_ceil(8)` bytes of `output`. Constant time with
/// respect to the input exactly when the digest is: it loops on public lengths
/// and shifts by a public amount.
pub(crate) fn hash_df<D: Digest>(
    digest: &mut D,
    parts: &[&[u8]],
    output: &mut [u8],
    output_bits: usize,
) -> Result<(), DrbgError> {
    let bits = u32::try_from(output_bits).map_err(|_| DrbgError::InputTooLong)?;
    let output = &mut output[..output_bits.div_ceil(8)];
    let digest_size = digest.digest_size();
    if digest_size == 0 || digest_size > MAX_OUTPUT_SIZE {
        return Err(DrbgError::UnsupportedOutputSize(digest_size));
    }

    let mut hash = Zeroizing::new([0; MAX_OUTPUT_SIZE]);
    let mut counter = 1_u8;
    for chunk in output.chunks_mut(digest_size) {
        digest.update_byte(counter);
        digest.update(&bits.to_be_bytes());
        for part in parts {
            digest.update(part);
        }
        digest.do_final(&mut hash[..digest_size]);
        chunk.copy_from_slice(&hash[..chunk.len()]);
        counter = counter.checked_add(1).ok_or(DrbgError::InputTooLong)?;
    }

    let excess = (8 - output_bits % 8) % 8;
    if excess != 0 {
        let mut carry = 0_u8;
        for byte in output.iter_mut() {
            let current = *byte;
            *byte = (current >> excess) | carry;
            carry = current << (8 - excess);
        }
    }
    Ok(())
}

/// SP 800-90A §10.3.2 Block_Cipher_df over the concatenation of `parts`,
/// into all of `output`, which is at most [`MAX_CTR_SEED_LEN`] bytes.
/// Constant time with respect to the input exactly when the block cipher is:
/// it loops only on public lengths.
pub(crate) fn block_cipher_df<C>(
    cipher: &mut C,
    key_size: usize,
    parts: &[&[u8]],
    output: &mut [u8],
) -> Result<(), DrbgError>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    if cipher.block_size() != AES_BLOCK_SIZE {
        return Err(DrbgError::InvalidBlockSize(cipher.block_size()));
    }
    let input_len = u32::try_from(total_len(parts)?).map_err(|_| DrbgError::InputTooLong)?;
    let requested_len = u32::try_from(output.len()).map_err(|_| DrbgError::InputTooLong)?;
    let mut header = [0; 8];
    header[..4].copy_from_slice(&input_len.to_be_bytes());
    header[4..].copy_from_slice(&requested_len.to_be_bytes());

    cipher
        .init(CipherDirection::Encrypt, &KeyRef::new(&K_BITS[..key_size]))
        .map_err(|_| DrbgError::CipherFailure)?;

    let temp_len = key_size + AES_BLOCK_SIZE;
    let mut temp = Zeroizing::new([0; MAX_CTR_SEED_LEN]);
    for (counter, chunk) in temp[..temp_len].chunks_mut(AES_BLOCK_SIZE).enumerate() {
        let mut iv = [0; AES_BLOCK_SIZE];
        let counter = u32::try_from(counter).map_err(|_| DrbgError::InputTooLong)?;
        iv[..4].copy_from_slice(&counter.to_be_bytes());
        let mut bcc = Bcc::new();
        bcc.absorb(cipher, &iv)?;
        bcc.absorb(cipher, &header)?;
        for part in parts {
            bcc.absorb(cipher, part)?;
        }
        bcc.absorb(cipher, &[0x80])?;
        bcc.finish(cipher)?;
        chunk.copy_from_slice(&bcc.chaining[..chunk.len()]);
    }

    cipher
        .init(CipherDirection::Encrypt, &KeyRef::new(&temp[..key_size]))
        .map_err(|_| DrbgError::CipherFailure)?;
    let mut x = Zeroizing::new([0; AES_BLOCK_SIZE]);
    x.copy_from_slice(&temp[key_size..temp_len]);
    for chunk in output.chunks_mut(AES_BLOCK_SIZE) {
        let mut next = Zeroizing::new([0; AES_BLOCK_SIZE]);
        process(cipher, &x[..], &mut next[..])?;
        x.copy_from_slice(&next[..]);
        chunk.copy_from_slice(&next[..chunk.len()]);
    }
    Ok(())
}

/// Encrypts one AES block. Constant time exactly when the block cipher is.
pub(crate) fn process<C: BlockCipher>(
    cipher: &mut C,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), DrbgError> {
    let written = cipher
        .process_block(input, output)
        .map_err(|_| DrbgError::CipherFailure)?;
    if written != AES_BLOCK_SIZE {
        return Err(DrbgError::CipherFailure);
    }
    Ok(())
}

/// SP 800-90A §10.3.3 BCC, fed in pieces so the padded input is never
/// assembled: a CBC-MAC with a zero IV, wiped on drop.
struct Bcc {
    chaining: Zeroizing<[u8; AES_BLOCK_SIZE]>,
    block: Zeroizing<[u8; AES_BLOCK_SIZE]>,
    filled: usize,
}

impl Bcc {
    /// A chain of zeros with nothing buffered. Constant time.
    fn new() -> Self {
        Self {
            chaining: Zeroizing::new([0; AES_BLOCK_SIZE]),
            block: Zeroizing::new([0; AES_BLOCK_SIZE]),
            filled: 0,
        }
    }

    /// Adds `bytes`, chaining each block as it fills. Constant time with
    /// respect to the bytes exactly when the block cipher is: it branches only
    /// on how much is buffered.
    fn absorb<C: BlockCipher>(
        &mut self,
        cipher: &mut C,
        mut bytes: &[u8],
    ) -> Result<(), DrbgError> {
        while !bytes.is_empty() {
            let take = core::cmp::min(AES_BLOCK_SIZE - self.filled, bytes.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&bytes[..take]);
            self.filled += take;
            bytes = &bytes[take..];
            if self.filled == AES_BLOCK_SIZE {
                self.chain(cipher)?;
            }
        }
        Ok(())
    }

    /// Pads the last block with zeros and chains it, when one is started.
    /// Constant time exactly when the block cipher is.
    fn finish<C: BlockCipher>(&mut self, cipher: &mut C) -> Result<(), DrbgError> {
        if self.filled != 0 {
            self.block[self.filled..].fill(0);
            self.chain(cipher)?;
        }
        Ok(())
    }

    /// `chaining = E(chaining XOR block)`. Constant time exactly when the
    /// block cipher is.
    fn chain<C: BlockCipher>(&mut self, cipher: &mut C) -> Result<(), DrbgError> {
        for (block, chaining) in self.block.iter_mut().zip(self.chaining.iter()) {
            *block ^= chaining;
        }
        process(cipher, &self.block[..], &mut self.chaining[..])?;
        self.filled = 0;
        Ok(())
    }
}
