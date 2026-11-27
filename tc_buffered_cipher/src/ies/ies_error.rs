use alloc::boxed::Box;
use core::error::Error;
use core::fmt;

/// The error of the primitive underneath, boxed: IES runs an agreement, a KDF, a MAC and
/// perhaps a cipher, each with error types of its own, too many to carry as type parameters.
pub type PrimitiveError = Box<dyn Error + Send + Sync>;

/// A failure while initializing IES or processing a message.
#[derive(Debug)]
#[non_exhaustive]
pub enum IesError {
    /// The engine has not been initialized.
    NotInitialised,
    /// A key length is not a whole number of bytes; the field holds the bits given. BC
    /// truncates such a length instead.
    InvalidKeyLength(usize),
    /// The input to decrypt is shorter than the MAC.
    InputTooShort,
    /// The MAC over the ciphertext does not match.
    InvalidMac,
    /// The key agreement failed, such as on a public key of another curve.
    Agreement(PrimitiveError),
    /// The KDF failed.
    Kdf(PrimitiveError),
    /// The MAC failed.
    Mac(PrimitiveError),
    /// The block cipher failed, such as on corrupt padding after a valid MAC.
    Cipher(PrimitiveError),
}

impl fmt::Display for IesError {
    /// Writes a description of this layer only; the primitive's error is reachable through
    /// `source`. Constant time: no field holds secret data.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialised => f.write_str("IES not initialised"),
            Self::InvalidKeyLength(bits) => {
                write!(
                    f,
                    "IES key length must be a whole number of bytes, not {bits} bits"
                )
            }
            Self::InputTooShort => f.write_str("IES input is shorter than the MAC"),
            Self::InvalidMac => f.write_str("IES MAC does not match"),
            Self::Agreement(_) => f.write_str("IES key agreement failed"),
            Self::Kdf(_) => f.write_str("IES KDF failed"),
            Self::Mac(_) => f.write_str("IES MAC failed"),
            Self::Cipher(_) => f.write_str("IES cipher failed"),
        }
    }
}

impl Error for IesError {
    /// Returns the primitive's error for the variants that wrap one, and `None` otherwise.
    /// Constant time.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Agreement(error) | Self::Kdf(error) | Self::Mac(error) | Self::Cipher(error) => {
                Some(&**error)
            }
            _ => None,
        }
    }
}
