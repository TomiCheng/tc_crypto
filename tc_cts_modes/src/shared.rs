use tc_block_cipher::BlockCipher;
use tc_buffered_cipher::BufferedError;

/// The state both types share, borrowed from their own storage: two blocks of `buffer`, and one
/// block each of `chain`, `next` and `block`.
pub(crate) struct Buffers<'a> {
    pub(crate) buffer: &'a mut [u8],
    pub(crate) chain: &'a mut [u8],
    pub(crate) next: &'a mut [u8],
    pub(crate) block: &'a mut [u8],
}

/// Bouncy Castle's `GetUpdateOutputSize`, but exact: the buffer always keeps more than one and
/// at most two blocks, and whole blocks beyond them are written. Zero for a block size of zero.
/// Constant time: reads only lengths.
pub(crate) fn update_output_len<E>(
    buffered: usize,
    block_size: usize,
    input_len: usize,
) -> Result<usize, BufferedError<E>> {
    let total = buffered
        .checked_add(input_len)
        .ok_or(BufferedError::InputTooLong)?;
    if block_size == 0 || total <= block_size {
        return Ok(0);
    }
    Ok((total - block_size - 1) / block_size * block_size)
}

/// Bouncy Castle's `GetOutputSize`: what is buffered plus the new input, as the output of CTS is
/// as long as its input. Constant time: reads only lengths.
pub(crate) fn output_len<E>(buffered: usize, input_len: usize) -> Result<usize, BufferedError<E>> {
    buffered
        .checked_add(input_len)
        .ok_or(BufferedError::InputTooLong)
}

/// Bouncy Castle's `m_cipherMode.ProcessBlock`: ECB hands the block to the block cipher; CBC
/// encrypts the XOR with `chain` and keeps the ciphertext, and decrypts and XORs with `chain`,
/// which becomes this ciphertext. Constant time exactly when the block cipher is: it adds only
/// XORs and copies.
fn process_mode<C: BlockCipher>(
    cipher: &mut C,
    cbc: bool,
    encrypting: bool,
    chain: &mut [u8],
    next: &mut [u8],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), C::Error> {
    let n = chain.len();
    if !cbc {
        cipher.process_block(input, output)?;
    } else if encrypting {
        for (chain, input) in chain.iter_mut().zip(input) {
            *chain ^= input;
        }
        cipher.process_block(chain, output)?;
        chain.copy_from_slice(&output[..n]);
    } else {
        next.copy_from_slice(&input[..n]);
        cipher.process_block(input, output)?;
        for (output, chain) in output.iter_mut().zip(chain.iter()) {
            *output ^= chain;
        }
        chain.copy_from_slice(next);
    }
    Ok(())
}

/// Bouncy Castle's `ProcessBytes`: when the buffer holds two blocks and more input arrives, the
/// earlier block is written, leaving at most the last two blocks for `do_final`. Constant time
/// exactly when the block cipher is: it branches only on lengths, and copies.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_bytes<C: BlockCipher>(
    cipher: &mut C,
    cbc: bool,
    encrypting: bool,
    buffers: Buffers<'_>,
    buffered: &mut usize,
    mut input: &[u8],
    output: &mut [u8],
) -> Result<usize, BufferedError<C::Error>> {
    let Buffers {
        buffer,
        chain,
        next,
        ..
    } = buffers;
    let n = chain.len();
    let required = update_output_len(*buffered, n, input.len())?;
    if output.len() < required {
        return Err(BufferedError::OutputTooShort {
            required,
            available: output.len(),
        });
    }
    let mut written = 0;
    let available = buffer.len() - *buffered;
    if input.len() > available {
        buffer[*buffered..].copy_from_slice(&input[..available]);
        input = &input[available..];
        process_mode(
            cipher,
            cbc,
            encrypting,
            chain,
            next,
            &buffer[..n],
            &mut output[..n],
        )
        .map_err(BufferedError::Cipher)?;
        buffer.copy_within(n.., 0);
        *buffered = n;
        written = n;
        while input.len() > n {
            process_mode(
                cipher,
                cbc,
                encrypting,
                chain,
                next,
                &buffer[..n],
                &mut output[written..written + n],
            )
            .map_err(BufferedError::Cipher)?;
            written += n;
            buffer[..n].copy_from_slice(&input[..n]);
            input = &input[n..];
        }
    }
    buffer[*buffered..*buffered + input.len()].copy_from_slice(input);
    *buffered += input.len();
    Ok(written)
}

/// Bouncy Castle's `DoFinal`: at least one whole block is needed. Encrypting, the next-to-last
/// block goes through the mode; the partial last block is filled with the tail of that result,
/// XORed with it and encrypted by the block cipher alone, and comes first, with the ciphertext
/// of the next-to-last block cut short after it. Decrypting reverses this. Constant time
/// exactly when the block cipher is: it branches only on lengths, and copies.
pub(crate) fn do_final<C: BlockCipher>(
    cipher: &mut C,
    cbc: bool,
    encrypting: bool,
    buffers: Buffers<'_>,
    buffered: usize,
    output: &mut [u8],
) -> Result<usize, BufferedError<C::Error>> {
    let Buffers {
        buffer,
        chain,
        next,
        block,
    } = buffers;
    let n = chain.len();
    if buffered < n {
        return Err(BufferedError::IncompleteLastBlock);
    }
    if output.len() < buffered {
        return Err(BufferedError::OutputTooShort {
            required: buffered,
            available: output.len(),
        });
    }
    let tail = buffered - n;
    let (first, second) = buffer.split_at_mut(n);
    block.copy_from_slice(first);
    if encrypting {
        process_mode(cipher, cbc, true, chain, next, block, first)
            .map_err(BufferedError::Cipher)?;
        for (index, (second, first)) in second.iter_mut().zip(first.iter()).enumerate() {
            if index < tail {
                *second ^= first;
            } else {
                *second = *first;
            }
        }
        cipher
            .process_block(second, &mut output[..n])
            .map_err(BufferedError::Cipher)?;
        output[n..buffered].copy_from_slice(&first[..tail]);
    } else {
        cipher
            .process_block(block, first)
            .map_err(BufferedError::Cipher)?;
        for (first, second) in first.iter_mut().zip(second.iter_mut()).take(tail) {
            let decrypted = *first;
            *first = *second;
            *second ^= decrypted;
        }
        process_mode(cipher, cbc, false, chain, next, first, &mut output[..n])
            .map_err(BufferedError::Cipher)?;
        output[n..buffered].copy_from_slice(&second[..tail]);
    }
    Ok(buffered)
}
