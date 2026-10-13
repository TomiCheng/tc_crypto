//! Shared cipher transformation direction.

/// The transformation direction selected during cipher initialization.
///
/// The block-cipher, stream-cipher and asymmetric-block-cipher contracts each
/// define a direction of their own; this one converts to and from all three
/// with `From`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherDirection {
    /// Transform plaintext into ciphertext.
    Encrypt,
    /// Transform ciphertext into plaintext.
    Decrypt,
}

impl From<tc_block_cipher::CipherDirection> for CipherDirection {
    /// Converts the block-cipher contract's direction. Constant time.
    fn from(direction: tc_block_cipher::CipherDirection) -> Self {
        match direction {
            tc_block_cipher::CipherDirection::Encrypt => Self::Encrypt,
            tc_block_cipher::CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}

impl From<CipherDirection> for tc_block_cipher::CipherDirection {
    /// Converts to the block-cipher contract's direction. Constant time.
    fn from(direction: CipherDirection) -> Self {
        match direction {
            CipherDirection::Encrypt => Self::Encrypt,
            CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}

impl From<tc_stream_cipher::CipherDirection> for CipherDirection {
    /// Converts the stream-cipher contract's direction. Constant time.
    fn from(direction: tc_stream_cipher::CipherDirection) -> Self {
        match direction {
            tc_stream_cipher::CipherDirection::Encrypt => Self::Encrypt,
            tc_stream_cipher::CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}

impl From<CipherDirection> for tc_stream_cipher::CipherDirection {
    /// Converts to the stream-cipher contract's direction. Constant time.
    fn from(direction: CipherDirection) -> Self {
        match direction {
            CipherDirection::Encrypt => Self::Encrypt,
            CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}

impl From<tc_asym_cipher::CipherDirection> for CipherDirection {
    /// Converts the asymmetric-block-cipher contract's direction. Constant time.
    fn from(direction: tc_asym_cipher::CipherDirection) -> Self {
        match direction {
            tc_asym_cipher::CipherDirection::Encrypt => Self::Encrypt,
            tc_asym_cipher::CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}

impl From<CipherDirection> for tc_asym_cipher::CipherDirection {
    /// Converts to the asymmetric-block-cipher contract's direction.
    /// Constant time.
    fn from(direction: CipherDirection) -> Self {
        match direction {
            CipherDirection::Encrypt => Self::Encrypt,
            CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}
