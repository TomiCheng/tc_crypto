//! Buffering logic shared by the allocating and fixed-size asymmetric adapters.

use tc_asym_cipher::AsymmetricBlockCipher;

use crate::{BufferedError, CipherDirection};

/// The bytes the buffer holds after `init`: the cipher's input block, and one
/// more when encrypting, which Bouncy Castle allows for callers who pad on
/// their own over a raw cipher. An encoding still turns the extra byte down.
pub(super) fn capacity<C: AsymmetricBlockCipher>(cipher: &C, direction: CipherDirection) -> usize {
    let extra = usize::from(direction == CipherDirection::Encrypt);
    cipher.input_block_size().saturating_add(extra)
}

/// Appends `input` to the `buffered` bytes of `buffer`, whose length is the
/// capacity; the buffer is left as it was when `input` does not fit.
pub(super) fn process_bytes<E>(
    buffer: &mut [u8],
    buffered: &mut usize,
    input: &[u8],
) -> Result<usize, BufferedError<E>> {
    let end = buffered
        .checked_add(input.len())
        .filter(|&end| end <= buffer.len())
        .ok_or(BufferedError::InputTooLong)?;
    buffer[*buffered..end].copy_from_slice(input);
    *buffered = end;
    Ok(0)
}

/// Passes `message` to the cipher as one block; an empty message writes
/// nothing, as in Bouncy Castle. The caller wipes the buffer afterwards.
pub(super) fn do_final<C: AsymmetricBlockCipher>(
    cipher: &mut C,
    message: &[u8],
    output: &mut [u8],
) -> Result<usize, BufferedError<C::Error>> {
    if message.is_empty() {
        return Ok(0);
    }
    let required = cipher.output_block_size();
    if output.len() < required {
        return Err(BufferedError::OutputTooShort {
            required,
            available: output.len(),
        });
    }
    cipher
        .process_block(message, output)
        .map_err(BufferedError::Cipher)
}
