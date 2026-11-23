use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::derivation::{AES_BLOCK_SIZE, MAX_CTR_SEED_LEN, block_cipher_df, process};
use crate::drbg::{
    check_request, read_entropy, rng_fill, rng_next_u32, rng_next_u64, total_len,
    validate_security_strength,
};
use crate::{Drbg, DrbgError};

/// NIST SP 800-90A §10.2.1 CTR_DRBG over AES, after Bouncy Castle's
/// `CtrSP800Drbg`, with or without the block cipher derivation function.
///
/// `Key` and `V` are kept inline and wiped on drop; the block cipher wipes its
/// own key schedule.
pub struct CtrDrbg<C> {
    cipher: C,
    key: [u8; 32],
    value: [u8; AES_BLOCK_SIZE],
    key_size: usize,
    seed_len: usize,
    entropy_size: usize,
    use_derivation_function: bool,
    reseed_counter: u64,
}

impl<C> CtrDrbg<C>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    /// Reads `entropy_size` bytes from `rng` and instantiates over `cipher`
    /// with an AES key of `key_size_bits`, through the block cipher
    /// derivation function, as Bouncy Castle always does.
    ///
    /// `security_strength` is in bits and at most the key size. Constant time
    /// with respect to the entropy and the state exactly when the block cipher
    /// is: it branches and loops only on lengths.
    ///
    /// # Errors
    ///
    /// [`DrbgError::InvalidKeySize`] or [`DrbgError::InvalidBlockSize`] when
    /// the cipher is not AES-128, AES-192 or AES-256;
    /// [`DrbgError::UnsupportedSecurityStrength`],
    /// [`DrbgError::InsufficientEntropy`] or [`DrbgError::ExcessiveEntropy`]
    /// for a strength or entropy size out of range (entropy is at most 256
    /// bytes); [`DrbgError::CipherFailure`] when the cipher fails.
    pub fn new_with_derivation_function<R: CryptoRng + ?Sized>(
        cipher: C,
        key_size_bits: usize,
        security_strength: usize,
        entropy_size: usize,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        Self::new(
            cipher,
            key_size_bits,
            security_strength,
            entropy_size,
            true,
            rng,
            nonce,
            personalization,
        )
    }

    /// As [`CtrDrbg::new_with_derivation_function`], but without the
    /// derivation function: the entropy, `nonce` and `personalization`
    /// together must be exactly seedlen bytes, the key size plus 16. Constant
    /// time with respect to the entropy and the state exactly when the block
    /// cipher is.
    ///
    /// # Errors
    ///
    /// As [`CtrDrbg::new_with_derivation_function`], and
    /// [`DrbgError::InvalidSeedLength`] when the seed material is not seedlen
    /// bytes.
    pub fn new_without_derivation_function<R: CryptoRng + ?Sized>(
        cipher: C,
        key_size_bits: usize,
        security_strength: usize,
        entropy_size: usize,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        Self::new(
            cipher,
            key_size_bits,
            security_strength,
            entropy_size,
            false,
            rng,
            nonce,
            personalization,
        )
    }

    /// The body of both constructors. Constant time exactly when the block
    /// cipher is.
    #[allow(clippy::too_many_arguments)]
    fn new<R: CryptoRng + ?Sized>(
        cipher: C,
        key_size_bits: usize,
        security_strength: usize,
        entropy_size: usize,
        use_derivation_function: bool,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        let key_size = match key_size_bits {
            128 | 192 | 256 => key_size_bits / 8,
            _ => return Err(DrbgError::InvalidKeySize(key_size_bits)),
        };
        let block_size = cipher.block_size();
        if block_size != AES_BLOCK_SIZE {
            return Err(DrbgError::InvalidBlockSize(block_size));
        }
        validate_security_strength(security_strength, key_size_bits, entropy_size)?;

        let entropy = read_entropy(rng, entropy_size);
        let mut drbg = Self {
            cipher,
            key: [0; 32],
            value: [0; AES_BLOCK_SIZE],
            key_size,
            seed_len: key_size + AES_BLOCK_SIZE,
            entropy_size,
            use_derivation_function,
            reseed_counter: 1,
        };
        let mut seed = Zeroizing::new([0; MAX_CTR_SEED_LEN]);
        drbg.prepare_seed(
            &[&entropy[..entropy_size], nonce, personalization],
            &mut seed,
        )?;
        drbg.update(&seed)?;
        Ok(drbg)
    }

    /// Derives seedlen bytes of `seed` from `parts`, or, without the
    /// derivation function, copies `parts` when they are exactly seedlen
    /// bytes. Constant time exactly when the block cipher is: it branches only
    /// on lengths.
    fn prepare_seed(
        &mut self,
        parts: &[&[u8]],
        seed: &mut [u8; MAX_CTR_SEED_LEN],
    ) -> Result<(), DrbgError> {
        let seed = &mut seed[..self.seed_len];
        if self.use_derivation_function {
            return block_cipher_df(&mut self.cipher, self.key_size, parts, seed);
        }
        let actual = total_len(parts)?;
        if actual != seed.len() {
            return Err(DrbgError::InvalidSeedLength {
                expected: seed.len(),
                actual,
            });
        }
        let mut offset = 0;
        for part in parts {
            seed[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        Ok(())
    }

    /// CTR_DRBG_Update with the first seedlen bytes of `seed`. Constant time
    /// exactly when the block cipher is.
    fn update(&mut self, seed: &[u8; MAX_CTR_SEED_LEN]) -> Result<(), DrbgError> {
        self.cipher
            .init(
                CipherDirection::Encrypt,
                &KeyRef::new(&self.key[..self.key_size]),
            )
            .map_err(|_| DrbgError::CipherFailure)?;
        let mut temp = Zeroizing::new([0; MAX_CTR_SEED_LEN]);
        let mut block = Zeroizing::new([0; AES_BLOCK_SIZE]);
        // AES-192's seedlen of 40 bytes ends in half a block
        for chunk in temp[..self.seed_len].chunks_mut(AES_BLOCK_SIZE) {
            increment(&mut self.value);
            process(&mut self.cipher, &self.value, &mut block[..])?;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        for (temp, seed) in temp.iter_mut().zip(seed.iter()) {
            *temp ^= seed;
        }
        self.key[..self.key_size].copy_from_slice(&temp[..self.key_size]);
        self.value
            .copy_from_slice(&temp[self.key_size..self.seed_len]);
        Ok(())
    }
}

impl<C> Drbg for CtrDrbg<C>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    /// CTR_DRBG_Generate. Constant time exactly when the block cipher is; see
    /// [`Drbg::generate`] for the errors.
    fn generate(&mut self, output: &mut [u8], additional_input: &[u8]) -> Result<(), DrbgError> {
        check_request(output.len(), self.reseed_counter)?;
        let mut seed = Zeroizing::new([0; MAX_CTR_SEED_LEN]);
        if !additional_input.is_empty() {
            self.prepare_seed(&[additional_input], &mut seed)?;
            self.update(&seed)?;
        }

        self.cipher
            .init(
                CipherDirection::Encrypt,
                &KeyRef::new(&self.key[..self.key_size]),
            )
            .map_err(|_| DrbgError::CipherFailure)?;
        let mut block = Zeroizing::new([0; AES_BLOCK_SIZE]);
        for chunk in output.chunks_mut(AES_BLOCK_SIZE) {
            increment(&mut self.value);
            process(&mut self.cipher, &self.value, &mut block[..])?;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }

        self.update(&seed)?;
        self.reseed_counter += 1;
        Ok(())
    }

    /// CTR_DRBG_Reseed. Constant time exactly when the block cipher is; see
    /// [`Drbg::reseed`] for the errors.
    fn reseed<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        let entropy = read_entropy(rng, self.entropy_size);
        let mut seed = Zeroizing::new([0; MAX_CTR_SEED_LEN]);
        self.prepare_seed(
            &[&entropy[..self.entropy_size], additional_input],
            &mut seed,
        )?;
        self.update(&seed)?;
        self.reseed_counter = 1;
        Ok(())
    }
}

impl<C> TryRng for CtrDrbg<C>
where
    C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>>,
{
    type Error = DrbgError;

    /// Four bytes from one request. Constant time exactly when the block
    /// cipher is; fails as [`Drbg::generate`] does.
    fn try_next_u32(&mut self) -> Result<u32, DrbgError> {
        rng_next_u32(self)
    }

    /// Eight bytes from one request. Constant time exactly when the block
    /// cipher is; fails as [`Drbg::generate`] does.
    fn try_next_u64(&mut self) -> Result<u64, DrbgError> {
        rng_next_u64(self)
    }

    /// One request without additional input. Constant time exactly when the
    /// block cipher is; fails as [`Drbg::generate`] does, with
    /// [`DrbgError::RequestTooLarge`] past 32 KiB.
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), DrbgError> {
        rng_fill(self, output)
    }
}

impl<C> TryCryptoRng for CtrDrbg<C> where C: BlockCipher + for<'a> BlockCipherInit<KeyRef<'a>> {}

impl<C> Drop for CtrDrbg<C> {
    /// Wipes `Key` and `V`. Constant time.
    fn drop(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
    }
}

/// `V = (V + 1) mod 2^128`, big-endian. Constant time: the carry is computed
/// without branches.
fn increment(value: &mut [u8]) {
    let mut carry = 1_u16;
    for byte in value.iter_mut().rev() {
        carry += u16::from(*byte);
        *byte = carry as u8;
        carry >>= 8;
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_core::{TryCryptoRng, TryRng};
    use tc_aes::AesEngine;

    use super::*;
    use crate::drbg::RESEED_MAX;

    struct ZeroRng;

    impl TryRng for ZeroRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            output.fill(0);
            Ok(())
        }
    }

    impl TryCryptoRng for ZeroRng {}

    #[test]
    fn generate_reports_the_reseed_limit() {
        let mut drbg = CtrDrbg::new_with_derivation_function(
            AesEngine::new(),
            128,
            128,
            16,
            &mut ZeroRng,
            &[0; 8],
            &[],
        )
        .unwrap();
        drbg.reseed_counter = RESEED_MAX + 1;

        assert_eq!(
            drbg.generate(&mut [0; 1], &[]),
            Err(DrbgError::ReseedRequired)
        );
    }

    #[test]
    fn incrementing_wraps_around() {
        let mut value = [0xff; 16];
        increment(&mut value);
        assert_eq!(value, [0; 16]);
    }
}
