use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_macs::{KeyRef, Mac, MacInit};
use tc_zeroize::Zeroize;

use crate::derivation::{MAX_OUTPUT_SIZE, max_hash_security_strength};
use crate::drbg::{
    all_empty, check_request, read_entropy, rng_fill, rng_next_u32, rng_next_u64,
    validate_security_strength,
};
use crate::{Drbg, DrbgError};

/// NIST SP 800-90A §10.1.2 HMAC_DRBG, after Bouncy Castle's `HMacSP800Drbg`.
///
/// `K` and `V` are kept inline, at most 64 bytes each, and wiped on drop.
pub struct HmacDrbg<M> {
    mac: M,
    key: [u8; MAX_OUTPUT_SIZE],
    value: [u8; MAX_OUTPUT_SIZE],
    output_size: usize,
    entropy_size: usize,
    reseed_counter: u64,
}

impl<M> HmacDrbg<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>>,
{
    /// Reads `entropy_size` bytes from `rng` and instantiates over `mac` with
    /// `nonce` and `personalization`.
    ///
    /// `security_strength` is in bits. Constant time with respect to the
    /// entropy and the state exactly when the MAC is: it branches and loops
    /// only on lengths.
    ///
    /// # Errors
    ///
    /// [`DrbgError::UnsupportedOutputSize`] when the MAC's output is not a SHA
    /// size; [`DrbgError::UnsupportedSecurityStrength`],
    /// [`DrbgError::InsufficientEntropy`] or [`DrbgError::ExcessiveEntropy`]
    /// for a strength or entropy size out of range (entropy is at most 256
    /// bytes); [`DrbgError::MacFailure`] when the MAC fails.
    pub fn new<R: CryptoRng + ?Sized>(
        mac: M,
        security_strength: usize,
        entropy_size: usize,
        rng: &mut R,
        nonce: &[u8],
        personalization: &[u8],
    ) -> Result<Self, DrbgError> {
        let output_size = mac.mac_size();
        let maximum = max_hash_security_strength(output_size)?;
        validate_security_strength(security_strength, maximum, entropy_size)?;

        let entropy = read_entropy(rng, entropy_size);
        let mut drbg = Self {
            mac,
            key: [0; MAX_OUTPUT_SIZE],
            value: [1; MAX_OUTPUT_SIZE],
            output_size,
            entropy_size,
            reseed_counter: 1,
        };
        drbg.update(&[&entropy[..entropy_size], nonce, personalization])?;
        Ok(drbg)
    }

    /// HMAC_DRBG_Update over the concatenation of `parts`. Constant time
    /// exactly when the MAC is: it branches only on whether `parts` is empty.
    fn update(&mut self, parts: &[&[u8]]) -> Result<(), DrbgError> {
        self.update_round(0x00, parts)?;
        if !all_empty(parts) {
            self.update_round(0x01, parts)?;
        }
        Ok(())
    }

    /// `K = HMAC(K, V || marker || parts)`, then `V = HMAC(K, V)`. Constant
    /// time exactly when the MAC is.
    fn update_round(&mut self, marker: u8, parts: &[&[u8]]) -> Result<(), DrbgError> {
        let n = self.output_size;
        self.mac
            .init(&KeyRef::new(&self.key[..n]))
            .map_err(|_| DrbgError::MacFailure)?;
        self.mac
            .update(&self.value[..n])
            .map_err(|_| DrbgError::MacFailure)?;
        self.mac
            .update(&[marker])
            .map_err(|_| DrbgError::MacFailure)?;
        for part in parts.iter().filter(|part| !part.is_empty()) {
            self.mac.update(part).map_err(|_| DrbgError::MacFailure)?;
        }
        finish(&mut self.mac, &mut self.key[..n])?;
        self.next_value()
    }

    /// `V = HMAC(K, V)`. Constant time exactly when the MAC is.
    fn next_value(&mut self) -> Result<(), DrbgError> {
        let n = self.output_size;
        self.mac
            .init(&KeyRef::new(&self.key[..n]))
            .map_err(|_| DrbgError::MacFailure)?;
        self.mac
            .update(&self.value[..n])
            .map_err(|_| DrbgError::MacFailure)?;
        finish(&mut self.mac, &mut self.value[..n])
    }
}

/// Writes the tag into `output`, which is exactly the MAC's size. Constant
/// time exactly when the MAC is.
fn finish<M: Mac>(mac: &mut M, output: &mut [u8]) -> Result<(), DrbgError> {
    let written = mac.do_final(output).map_err(|_| DrbgError::MacFailure)?;
    if written != output.len() {
        return Err(DrbgError::MacFailure);
    }
    Ok(())
}

impl<M> Drbg for HmacDrbg<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>>,
{
    /// HMAC_DRBG_Generate. Constant time exactly when the MAC is; see
    /// [`Drbg::generate`] for the errors.
    fn generate(&mut self, output: &mut [u8], additional_input: &[u8]) -> Result<(), DrbgError> {
        check_request(output.len(), self.reseed_counter)?;
        if !additional_input.is_empty() {
            self.update(&[additional_input])?;
        }
        for chunk in output.chunks_mut(self.output_size) {
            self.next_value()?;
            chunk.copy_from_slice(&self.value[..chunk.len()]);
        }
        self.update(&[additional_input])?;
        self.reseed_counter += 1;
        Ok(())
    }

    /// HMAC_DRBG_Reseed. Constant time exactly when the MAC is; see
    /// [`Drbg::reseed`] for the errors.
    fn reseed<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        additional_input: &[u8],
    ) -> Result<(), DrbgError> {
        let entropy = read_entropy(rng, self.entropy_size);
        self.update(&[&entropy[..self.entropy_size], additional_input])?;
        self.reseed_counter = 1;
        Ok(())
    }
}

impl<M> TryRng for HmacDrbg<M>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>>,
{
    type Error = DrbgError;

    /// Four bytes from one request. Constant time exactly when the MAC is;
    /// fails as [`Drbg::generate`] does.
    fn try_next_u32(&mut self) -> Result<u32, DrbgError> {
        rng_next_u32(self)
    }

    /// Eight bytes from one request. Constant time exactly when the MAC is;
    /// fails as [`Drbg::generate`] does.
    fn try_next_u64(&mut self) -> Result<u64, DrbgError> {
        rng_next_u64(self)
    }

    /// One request without additional input. Constant time exactly when the
    /// MAC is; fails as [`Drbg::generate`] does, with
    /// [`DrbgError::RequestTooLarge`] past 32 KiB.
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), DrbgError> {
        rng_fill(self, output)
    }
}

impl<M> TryCryptoRng for HmacDrbg<M> where M: Mac + for<'a> MacInit<KeyRef<'a>> {}

impl<M> Drop for HmacDrbg<M> {
    /// Wipes `K` and `V`; the MAC wipes its own key. Constant time.
    fn drop(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use rand_core::{Rng, TryCryptoRng, TryRng, UnwrapErr};
    use tc_macs::Hmac;
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

    fn drbg() -> HmacDrbg<Hmac<Sha256Digest>> {
        HmacDrbg::new(
            Hmac::new(Sha256Digest::new()),
            256,
            32,
            &mut ZeroRng,
            &[0; 16],
            &[],
        )
        .unwrap()
    }

    #[test]
    fn generate_reports_the_reseed_limit() {
        let mut drbg = drbg();
        drbg.reseed_counter = RESEED_MAX + 1;

        assert_eq!(
            drbg.generate(&mut [0; 1], &[]),
            Err(DrbgError::ReseedRequired)
        );
    }

    #[test]
    fn the_rand_core_interface_reports_a_required_reseed_as_an_error() {
        let mut drbg = drbg();
        drbg.reseed_counter = RESEED_MAX + 1;

        assert_eq!(
            drbg.try_fill_bytes(&mut [0; 1]),
            Err(DrbgError::ReseedRequired)
        );
        assert_eq!(drbg.try_next_u64(), Err(DrbgError::ReseedRequired));
    }

    #[test]
    fn the_rand_core_interface_reports_a_request_over_32_kib_as_an_error() {
        assert_eq!(
            drbg().try_fill_bytes(&mut [0; 32 * 1024 + 1]),
            Err(DrbgError::RequestTooLarge {
                requested: 32 * 1024 + 1,
                maximum: 32 * 1024,
            })
        );
    }

    #[test]
    #[should_panic(expected = "rand_core::UnwrapErr")]
    fn unwrap_err_turns_a_required_reseed_into_a_panic() {
        let mut drbg = drbg();
        drbg.reseed_counter = RESEED_MAX + 1;

        UnwrapErr(&mut drbg).fill_bytes(&mut [0; 1]);
    }

    #[test]
    fn a_reseed_restarts_the_request_count() {
        let mut drbg = drbg();
        drbg.reseed_counter = RESEED_MAX + 1;

        drbg.reseed(&mut ZeroRng, &[]).unwrap();
        assert!(drbg.generate(&mut [0; 1], &[]).is_ok());
    }
}
