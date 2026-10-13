//! Buffered-cipher processing error type.

use core::convert::Infallible;
use core::error::Error;
use core::fmt;

/// A failure of a buffered adapter; `E` is the wrapped cipher's processing
/// error, `Infallible` where there is none.
///
/// The AEAD adapters report their engine's own error instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BufferedError<E = Infallible> {
    /// Processing was requested before successful initialization.
    NotInitialized,
    /// The output buffer is shorter than required.
    OutputTooShort {
        /// The output length the call needs, in bytes.
        required: usize,
        /// The length of the output buffer that was supplied, in bytes.
        available: usize,
    },
    /// The length of the input exceeds what can be counted, or, for an
    /// asymmetric cipher, what one block takes.
    InputTooLong,
    /// Finalization found a trailing partial block it cannot resolve.
    ///
    /// Decrypting a padded message requires a whole number of blocks, and an
    /// unpadded mode that rejects partial blocks requires the same.
    IncompleteLastBlock,
    /// The padding on the final block was rejected.
    ///
    /// Callers must not report this separately from an authentication failure:
    /// distinguishing the two is what a padding oracle needs.
    CorruptPadding,
    /// The padding scheme could not pad the final block.
    PaddingFailed,
    /// A fixed-size adapter's buffer is shorter than the cipher needs under the
    /// key given to `init`.
    BufferTooSmall {
        /// The buffer length the cipher needs, in bytes.
        required: usize,
        /// The length of the adapter's buffer, in bytes.
        available: usize,
    },
    /// The wrapped cipher failed; [`source`](Error::source) returns its error.
    Cipher(E),
}

impl<E> fmt::Display for BufferedError<E> {
    /// Writes a description of this layer only; the cipher's error is reachable
    /// through `source`. Constant time: the fields hold only public lengths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("buffered cipher not initialized"),
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "output buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::InputTooLong => f.write_str("buffered cipher input length limit exceeded"),
            Self::IncompleteLastBlock => f.write_str("last block incomplete"),
            Self::CorruptPadding => f.write_str("pad block corrupted"),
            Self::PaddingFailed => f.write_str("padding could not be added"),
            Self::BufferTooSmall {
                required,
                available,
            } => write!(
                f,
                "fixed buffer is too short: requires {required} bytes, has {available}"
            ),
            Self::Cipher(_) => f.write_str("underlying cipher failed"),
        }
    }
}

impl<E: Error + 'static> Error for BufferedError<E> {
    /// Returns the cipher's error for `Cipher`, and `None` otherwise. Constant time.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cipher(error) => Some(error),
            _ => None,
        }
    }
}
