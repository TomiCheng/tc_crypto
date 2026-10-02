use crate::CipherDirection;
use core::error::Error;

/// A cipher that takes input in pieces of any size and finishes in
/// [`do_final`](Self::do_final), whatever its family: a block-cipher mode with
/// or without padding, a stream cipher or an AEAD.
///
/// This is the Rust form of Bouncy Castle's `IBufferedCipher`. An adapter holds
/// back what its cipher cannot process yet, such as a partial block, so one
/// call may write less than it reads; the sizing methods say how much to
/// expect.
///
/// As in Bouncy Castle, an AEAD takes its associated data only through the
/// initial associated data of its parameters, and its tag is part of the
/// output. The AEAD contract itself offers more, such as `mac()`.
///
/// Each adapter documents its timing; this contract adds no work of its own.
pub trait BufferedCipher {
    /// The error returned while processing a message.
    type Error: Error;

    /// Returns the block size of the underlying cipher in bytes, or zero for a
    /// stream cipher or an AEAD that is not built on a block cipher.
    fn block_size(&self) -> usize;

    /// Returns how many bytes [`process_bytes`](Self::process_bytes) writes for
    /// `input_len` further bytes of input, counting the input the adapter
    /// already holds.
    ///
    /// Fails when the count does not fit in `usize`.
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error>;

    /// Returns how many bytes `process_bytes` and `do_final` write together for
    /// `input_len` further bytes of input, counting the input the adapter
    /// already holds, any padding and any tag; `output_len(0)` sizes the
    /// `do_final` buffer. Adapters whose final length depends on the data,
    /// such as padded decryption, return an upper bound.
    ///
    /// Fails when the count does not fit in `usize`.
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error>;

    /// Processes one byte and returns the number of bytes written, usually
    /// zero while a block fills up.
    ///
    /// The default passes a one-byte slice to `process_bytes`.
    fn process_byte(&mut self, input: u8, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.process_bytes(&[input], output)
    }

    /// Processes `input`, writes the output that is ready and returns its
    /// length.
    ///
    /// `output` must hold at least
    /// [`update_output_len`](Self::update_output_len) of `input.len()` bytes.
    /// When an AEAD decrypts, the output is not authenticated until `do_final`
    /// succeeds; discard it if `do_final` fails.
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Finishes the message, writes the remaining output and returns its
    /// length.
    ///
    /// This is where padding is added or removed, a trailing partial block is
    /// resolved and an AEAD tag is appended or verified. `output` must hold at
    /// least [`output_len`](Self::output_len) of `0` bytes. A failed call must
    /// not leave unverified plaintext in `output`.
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Discards the current message and returns to the state right after
    /// `init`, when the underlying cipher allows it. An AEAD encryption that
    /// may already have released output under its nonce stays finalized until
    /// the next `init`.
    fn reset(&mut self);
}

/// Prepares a [`BufferedCipher`] from a parameter value of type `P`.
///
/// Parameter types only carry values; the underlying cipher validates them in
/// `init`.
pub trait BufferedCipherInit<P: ?Sized> {
    /// The error returned when `init` rejects the parameters or the underlying
    /// cipher fails to key itself.
    type Error: Error;

    /// Starts a new message in `direction` under `params`, discarding any
    /// previous state.
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error>;
}
