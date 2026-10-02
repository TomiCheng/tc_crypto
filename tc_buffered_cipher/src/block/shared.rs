//! Buffering logic shared by the allocating and fixed-size block adapters.

use tc_block_modes::BlockCipherMode;
use tc_block_padding::BlockCipherPadding;

use crate::BufferedError;

/// `hold_last` keeps a completed final block back for `do_final`, as padding
/// needs; without it every complete block is processed at once.
pub(super) fn update_output_len<E>(
    buffered: usize,
    block_size: usize,
    input_len: usize,
    hold_last: bool,
) -> Result<usize, BufferedError<E>> {
    let total = buffered
        .checked_add(input_len)
        .ok_or(BufferedError::InputTooLong)?;
    let left_over = total % block_size;
    Ok(if hold_last && left_over == 0 {
        total.saturating_sub(block_size)
    } else {
        total - left_over
    })
}

pub(super) fn output_len<E>(buffered: usize, input_len: usize) -> Result<usize, BufferedError<E>> {
    buffered
        .checked_add(input_len)
        .ok_or(BufferedError::InputTooLong)
}

pub(super) fn padded_output_len<E>(
    buffered: usize,
    block_size: usize,
    input_len: usize,
    encrypting: bool,
) -> Result<usize, BufferedError<E>> {
    let total = buffered
        .checked_add(input_len)
        .ok_or(BufferedError::InputTooLong)?;
    let left_over = total % block_size;
    if left_over == 0 && !encrypting {
        return Ok(total);
    }
    (total - left_over)
        .checked_add(block_size)
        .ok_or(BufferedError::InputTooLong)
}

pub(super) fn process_bytes<C: BlockCipherMode>(
    cipher_mode: &mut C,
    buffer: &mut [u8],
    buffered: &mut usize,
    mut input: &[u8],
    output: &mut [u8],
    hold_last: bool,
) -> Result<usize, BufferedError<C::Error>> {
    if input.is_empty() {
        return Ok(0);
    }

    let block_size = buffer.len();
    let required = update_output_len(*buffered, block_size, input.len(), hold_last)?;
    if output.len() < required {
        return Err(BufferedError::OutputTooShort {
            required,
            available: output.len(),
        });
    }

    // Whether `len` more bytes complete a block of `room` bytes that may go out now.
    let releases = |len: usize, room: usize| len > room || (!hold_last && len == room);
    let available = block_size - *buffered;
    let mut written = 0;

    if releases(input.len(), available) {
        buffer[*buffered..].copy_from_slice(&input[..available]);
        input = &input[available..];
        *buffered = 0;

        written += cipher_mode
            .process_block(buffer, &mut output[written..])
            .map_err(BufferedError::Cipher)?;

        while releases(input.len(), block_size) {
            written += cipher_mode
                .process_block(input, &mut output[written..])
                .map_err(BufferedError::Cipher)?;
            input = &input[block_size..];
        }
    }

    let end = *buffered + input.len();
    buffer[*buffered..end].copy_from_slice(input);
    *buffered = end;
    Ok(written)
}

/// Resolves the trailing partial block through `scratch`, which must be as
/// long as `buffer`; the caller wipes both afterwards.
pub(super) fn do_final<C: BlockCipherMode>(
    cipher_mode: &mut C,
    buffer: &mut [u8],
    scratch: &mut [u8],
    buffered: usize,
    output: &mut [u8],
) -> Result<usize, BufferedError<C::Error>> {
    if buffered == 0 {
        return Ok(0);
    }
    if !cipher_mode.is_partial_block_okay() {
        return Err(BufferedError::IncompleteLastBlock);
    }
    if output.len() < buffered {
        return Err(BufferedError::OutputTooShort {
            required: buffered,
            available: output.len(),
        });
    }

    buffer[buffered..].fill(0);
    cipher_mode
        .process_block(buffer, scratch)
        .map_err(BufferedError::Cipher)?;
    output[..buffered].copy_from_slice(&scratch[..buffered]);
    Ok(buffered)
}

/// Pads and encrypts, or decrypts and unpads, the held-back final block. The
/// caller wipes `buffer` and `scratch` afterwards.
pub(super) fn padded_do_final<C: BlockCipherMode, P: BlockCipherPadding>(
    cipher_mode: &mut C,
    padding: &mut P,
    buffer: &mut [u8],
    scratch: &mut [u8],
    buffered: usize,
    encrypting: bool,
    output: &mut [u8],
) -> Result<usize, BufferedError<C::Error>> {
    let block_size = buffer.len();

    if encrypting {
        let required = padded_output_len(buffered, block_size, 0, true)?;
        if output.len() < required {
            return Err(BufferedError::OutputTooShort {
                required,
                available: output.len(),
            });
        }

        let mut written = 0;
        let mut position = buffered;
        // A full final block goes out as is and a block of padding alone
        // follows, whatever the scheme, as in Bouncy Castle.
        if position == block_size {
            written += cipher_mode
                .process_block(buffer, output)
                .map_err(BufferedError::Cipher)?;
            position = 0;
        }
        padding
            .add_padding(buffer, position)
            .map_err(|_| BufferedError::PaddingFailed)?;
        written += cipher_mode
            .process_block(buffer, &mut output[written..])
            .map_err(BufferedError::Cipher)?;
        return Ok(written);
    }

    if buffered != block_size {
        return Err(BufferedError::IncompleteLastBlock);
    }
    cipher_mode
        .process_block(buffer, scratch)
        .map_err(BufferedError::Cipher)?;
    let pad = padding
        .pad_count(scratch)
        .map_err(|_| BufferedError::CorruptPadding)?;
    let message_len = block_size
        .checked_sub(pad)
        .ok_or(BufferedError::CorruptPadding)?;
    if output.len() < message_len {
        return Err(BufferedError::OutputTooShort {
            required: message_len,
            available: output.len(),
        });
    }
    output[..message_len].copy_from_slice(&scratch[..message_len]);
    Ok(message_len)
}
