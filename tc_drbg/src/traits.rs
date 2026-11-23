use rand_core::CryptoRng;

use crate::DrbgError;

/// The operations every NIST SP 800-90A DRBG shares.
pub trait Drbg {
    /// Fills `output` with random bytes, mixing in `additional_input` first.
    ///
    /// Constant time with respect to the state, the entropy and the output
    /// exactly when the underlying primitive is: it branches and loops only on
    /// lengths and on the request count, which are public.
    ///
    /// # Errors
    ///
    /// - [`DrbgError::RequestTooLarge`] when `output` is longer than 32 KiB
    ///   (2^18 bits). Ask in several calls for more.
    /// - [`DrbgError::ReseedRequired`] once 2^47 requests have been made since
    ///   the last seeding, and on every call after until [`Drbg::reseed`]. The
    ///   generator holds no entropy source, so it never reseeds on its own.
    ///   Each call of `generate`, `try_fill_bytes`, `try_next_u32` or
    ///   `try_next_u64` counts once, whatever its length, and `reseed` restarts
    ///   the count. Reseed before the limit, or periodically (for example once
    ///   per generated key), to avoid it.
    /// - [`DrbgError::MacFailure`] or [`DrbgError::CipherFailure`] when the
    ///   underlying primitive fails, and, for a CTR_DRBG without a derivation
    ///   function, [`DrbgError::InvalidSeedLength`] when `additional_input` is
    ///   neither empty nor seedlen bytes.
    fn generate(&mut self, output: &mut [u8], additional_input: &[u8]) -> Result<(), DrbgError>;

    /// Reseeds the state with entropy read from `rng` and `additional_input`,
    /// and restarts the request count.
    ///
    /// Constant time with respect to the state and the entropy exactly when
    /// the underlying primitive is: it branches and loops only on lengths.
    ///
    /// # Errors
    ///
    /// When the underlying primitive fails, or a CTR_DRBG without a derivation
    /// function gets seed material that is not seedlen bytes. The state may
    /// then be partly updated and must not be used to generate output.
    fn reseed<R: CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        additional_input: &[u8],
    ) -> Result<(), DrbgError>;
}
