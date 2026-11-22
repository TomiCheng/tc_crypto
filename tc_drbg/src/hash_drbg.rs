use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_digest::Digest;
use tc_zeroize::{Zeroize, Zeroizing};

use crate::derivation::{MAX_OUTPUT_SIZE, hash_df, hash_seed_bits, max_hash_security_strength};
use crate::drbg::{
    check_request, read_entropy, rng_fill, rng_next_u32, rng_next_u64, validate_security_strength,
};
use crate::{Drbg, DrbgError};

/// The longest Hash_DRBG seedlen, 888 bits.
const MAX_SEED_LEN: usize = 111;

/// NIST SP 800-90A §10.1.1 Hash_DRBG, after Bouncy Castle's `HashSP800Drbg`.
///
/// `V` and `C` are kept inline, at most 111 bytes each, and wiped on drop.
pub struct HashDrbg<D> {
    digest: D,
    value: [u8; MAX_SEED_LEN],
    constant: [u8; MAX_SEED_LEN],
    seed_bits: usize,
    seed_len: usize,
    entropy_size: usize,
    reseed_counter: u64,
}

impl<D: Digest> HashDrbg<D> {
    /// Reads `entropy_size` bytes from `rng` and instantiates over `digest`
    /// with `nonce` and `personalization`.
    ///
    /// `security_strength` is in bits. Constant time with respect to the
    /// entropy and the state exactly when the digest is: it branches and loops
    /// only on lengths.
    ///
    /// # Errors
    ///
    /// [`DrbgError::UnsupportedOutputSize`] when the digest's output is not a
    /// SHA size; [`DrbgError::UnsupportedSecurityStrength`],
    /// [`DrbgError::InsufficientEntropy`] or [`DrbgError::ExcessiveEntropy`]
    /// for a strength or entropy size out of range (entropy is at most 256
    /// bytes).
    pub fn new<R: CryptoRng + ?Sized>(
        mut digest: D,
        security_strength: usize,
        entropy_size: usize,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        let output_size = digest.digest_size();
        let maximum = max_hash_security_strength(output_size)?;
        validate_security_strength(security_strength, maximum, entropy_size)?;
        let seed_bits = hash_seed_bits(output_size);

        let entropy = read_entropy(rng, entropy_size);
        let mut value = [0; MAX_SEED_LEN];
        hash_df(
            &mut digest,
            &[&entropy[..entropy_size], nonce, personalization],
            &mut value,
            seed_bits,
        )?;
        let mut drbg = Self {
            digest,
            value,
            constant: [0; MAX_SEED_LEN],
            seed_bits,
            seed_len: seed_bits / 8,
            entropy_size,
            reseed_counter: 1,
        };
        value.zeroize();
        drbg.derive_constant()?;
        Ok(drbg)
    }

    /// `C = Hash_df(0x00 || V, seedlen)`. Constant time exactly when the
    /// digest is.
    fn derive_constant(&mut self) -> Result<(), DrbgError> {
        hash_df(
            &mut self.digest,
            &[&[0x00], &self.value[..self.seed_len]],
            &mut self.constant,
            self.seed_bits,
        )
    }

    /// Hashgen: fills `output` from `V`, leaving `V` as it was. Constant time
    /// exactly when the digest is.
    fn hashgen(&mut self, output: &mut [u8]) {
        let n = self.seed_len;
        let size = self.digest.digest_size();
        let mut data = Zeroizing::new(self.value);
        let mut hash = Zeroizing::new([0; MAX_OUTPUT_SIZE]);
        for chunk in output.chunks_mut(size) {
            self.digest.update(&data[..n]);
            self.digest.do_final(&mut hash[..size]);
            chunk.copy_from_slice(&hash[..chunk.len()]);
            add_to(&mut data[..n], &[1]);
        }
    }

    /// `V = V + Hash(prefix || V || extra)`. Constant time exactly when the
    /// digest is.
    fn add_hash(&mut self, prefix: u8, extra: &[u8]) {
        let n = self.seed_len;
        let size = self.digest.digest_size();
        let mut hash = Zeroizing::new([0; MAX_OUTPUT_SIZE]);
        self.digest.update_byte(prefix);
        self.digest.update(&self.value[..n]);
        self.digest.update(extra);
        self.digest.do_final(&mut hash[..size]);
        add_to(&mut self.value[..n], &hash[..size]);
    }
}

impl<D: Digest> Drbg for HashDrbg<D> {
    /// Hash_DRBG_Generate. Constant time exactly when the digest is; see
    /// [`Drbg::generate`] for the errors.
    fn generate(&mut self, output: &mut [u8], additional_input: &[u8]) -> Result<(), DrbgError> {
        check_request(output.len(), self.reseed_counter)?;
        if !additional_input.is_empty() {
            self.add_hash(0x02, additional_input);
        }
        self.hashgen(output);
        self.add_hash(0x03, &[]);
        let n = self.seed_len;
        add_to(&mut self.value[..n], &self.constant[..n]);
        // Bouncy Castle adds the count as 32 bits.
        add_to(
            &mut self.value[..n],
            &(self.reseed_counter as u32).to_be_bytes(),
        );
        self.reseed_counter += 1;
        Ok(())
    }

    /// Hash_DRBG_Reseed. Constant time exactly when the digest is; see
    /// [`Drbg::reseed`] for the errors.
    fn reseed<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        let entropy = read_entropy(rng, self.entropy_size);
        let mut value = Zeroizing::new([0; MAX_SEED_LEN]);
        hash_df(
            &mut self.digest,
            &[
                &[0x01],
                &self.value[..self.seed_len],
                &entropy[..self.entropy_size],
                additional_input,
            ],
            &mut value[..],
            self.seed_bits,
        )?;
        self.value.copy_from_slice(&value[..]);
        self.derive_constant()?;
        self.reseed_counter = 1;
        Ok(())
    }
}

impl<D: Digest> TryRng for HashDrbg<D> {
    type Error = DrbgError;

    /// Four bytes from one request. Constant time exactly when the digest is;
    /// fails as [`Drbg::generate`] does.
    fn try_next_u32(&mut self) -> Result<u32, DrbgError> {
        rng_next_u32(self)
    }

    /// Eight bytes from one request. Constant time exactly when the digest
    /// is; fails as [`Drbg::generate`] does.
    fn try_next_u64(&mut self) -> Result<u64, DrbgError> {
        rng_next_u64(self)
    }

    /// One request without additional input. Constant time exactly when the
    /// digest is; fails as [`Drbg::generate`] does, with
    /// [`DrbgError::RequestTooLarge`] past 32 KiB.
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), DrbgError> {
        rng_fill(self, output)
    }
}

impl<D: Digest> TryCryptoRng for HashDrbg<D> {}

impl<D> Drop for HashDrbg<D> {
    /// Wipes `V` and `C`. Constant time.
    fn drop(&mut self) {
        self.value.zeroize();
        self.constant.zeroize();
    }
}

/// `longer = (longer + shorter) mod 2^(8 * longer.len())`, both big-endian.
/// Constant time: the carry is computed without branches.
fn add_to(longer: &mut [u8], shorter: &[u8]) {
    debug_assert!(longer.len() >= shorter.len());
    let offset = longer.len() - shorter.len();
    let mut carry = 0_u16;
    for index in (0..shorter.len()).rev() {
        carry += u16::from(longer[offset + index]) + u16::from(shorter[index]);
        longer[offset + index] = carry as u8;
        carry >>= 8;
    }
    for byte in longer[..offset].iter_mut().rev() {
        carry += u16::from(*byte);
        *byte = carry as u8;
        carry >>= 8;
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_core::{TryCryptoRng, TryRng};
    use tc_sha::Sha256Digest;

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
        let mut drbg =
            HashDrbg::new(Sha256Digest::new(), 256, 32, &mut ZeroRng, &[0; 16], &[]).unwrap();
        drbg.reseed_counter = RESEED_MAX + 1;

        assert_eq!(
            drbg.generate(&mut [0; 1], &[]),
            Err(DrbgError::ReseedRequired)
        );
    }

    #[test]
    fn adding_carries_through_every_byte() {
        let mut value = [0x00, 0xff, 0xff];
        add_to(&mut value, &[0x01]);
        assert_eq!(value, [0x01, 0x00, 0x00]);
        let mut value = [0xff, 0xff];
        add_to(&mut value, &[0x00, 0x01]);
        assert_eq!(value, [0x00, 0x00]);
    }
}
