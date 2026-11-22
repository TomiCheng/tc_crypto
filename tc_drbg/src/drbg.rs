use rand_core::CryptoRng;
use tc_zeroize::Zeroizing;

use crate::{Drbg, DrbgError};

/// The most one request may ask for: 2^18 bits, as Bouncy Castle allows.
pub(crate) const MAX_REQUEST_BYTES: usize = (1 << 18) / 8;

/// The requests allowed between seedings, as Bouncy Castle allows.
pub(crate) const RESEED_MAX: u64 = 1 << 47;

/// The most entropy one seeding reads, in bytes. The entropy is used more than
/// once while seeding, so it is buffered, and the buffer is inline.
pub(crate) const MAX_ENTROPY_BYTES: usize = 256;

/// Checks the requested security strength against the primitive's and the
/// entropy size against both the strength and the buffer. Constant time:
/// reads only public sizes.
pub(crate) fn validate_security_strength(
    requested: usize,
    maximum: usize,
    entropy_size: usize,
) -> Result<(), DrbgError> {
    if requested > maximum {
        return Err(DrbgError::UnsupportedSecurityStrength { requested, maximum });
    }
    let required = requested.div_ceil(8);
    if entropy_size < required {
        return Err(DrbgError::InsufficientEntropy {
            required,
            provided: entropy_size,
        });
    }
    if entropy_size > MAX_ENTROPY_BYTES {
        return Err(DrbgError::ExcessiveEntropy {
            maximum: MAX_ENTROPY_BYTES,
            provided: entropy_size,
        });
    }
    Ok(())
}

/// Checks a request's length and the request count before any output.
/// Constant time: reads only the public length and count.
pub(crate) fn check_request(length: usize, reseed_counter: u64) -> Result<(), DrbgError> {
    if length > MAX_REQUEST_BYTES {
        return Err(DrbgError::RequestTooLarge {
            requested: length,
            maximum: MAX_REQUEST_BYTES,
        });
    }
    if reseed_counter > RESEED_MAX {
        return Err(DrbgError::ReseedRequired);
    }
    Ok(())
}

/// Reads `size` bytes of entropy into a buffer wiped on drop; the caller has
/// checked `size` against [`MAX_ENTROPY_BYTES`]. Constant time with respect to
/// the entropy: the time is the source's.
pub(crate) fn read_entropy<R: CryptoRng + ?Sized>(
    rng: &mut R,
    size: usize,
) -> Zeroizing<[u8; MAX_ENTROPY_BYTES]> {
    let mut entropy = Zeroizing::new([0; MAX_ENTROPY_BYTES]);
    rng.fill_bytes(&mut entropy[..size]);
    entropy
}

/// Whether every part is empty. Constant time: reads only lengths.
pub(crate) fn all_empty(parts: &[&[u8]]) -> bool {
    parts.iter().all(|part| part.is_empty())
}

/// The total length of `parts`, or `InputTooLong` past `usize`. Constant
/// time: reads only lengths.
pub(crate) fn total_len(parts: &[&[u8]]) -> Result<usize, DrbgError> {
    parts.iter().try_fold(0_usize, |total, part| {
        total.checked_add(part.len()).ok_or(DrbgError::InputTooLong)
    })
}

/// `try_fill_bytes` of the rand_core interface: a request without additional
/// input. Constant time exactly when `generate` is.
pub(crate) fn rng_fill<D: Drbg>(drbg: &mut D, output: &mut [u8]) -> Result<(), DrbgError> {
    drbg.generate(output, &[])
}

/// `try_next_u32`: four little-endian bytes from one request. Constant time
/// exactly when `generate` is.
pub(crate) fn rng_next_u32<D: Drbg>(drbg: &mut D) -> Result<u32, DrbgError> {
    let mut bytes = Zeroizing::new([0; 4]);
    drbg.generate(&mut bytes[..], &[])?;
    Ok(u32::from_le_bytes(*bytes))
}

/// `try_next_u64`: eight little-endian bytes from one request. Constant time
/// exactly when `generate` is.
pub(crate) fn rng_next_u64<D: Drbg>(drbg: &mut D) -> Result<u64, DrbgError> {
    let mut bytes = Zeroizing::new([0; 8]);
    drbg.generate(&mut bytes[..], &[])?;
    Ok(u64::from_le_bytes(*bytes))
}
