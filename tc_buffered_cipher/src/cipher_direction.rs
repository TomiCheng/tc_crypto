//! Shared cipher transformation direction.

/// The transformation direction selected during cipher initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherDirection {
    /// Transform plaintext into ciphertext.
    Encrypt,
    /// Transform ciphertext into plaintext.
    Decrypt,
}

impl From<tc_block_cipher::CipherDirection> for CipherDirection {
    fn from(direction: tc_block_cipher::CipherDirection) -> Self {
        match direction {
            tc_block_cipher::CipherDirection::Encrypt => Self::Encrypt,
            tc_block_cipher::CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}

impl From<CipherDirection> for tc_block_cipher::CipherDirection {
    fn from(direction: CipherDirection) -> Self {
        match direction {
            CipherDirection::Encrypt => Self::Encrypt,
            CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}

impl From<tc_stream_cipher::CipherDirection> for CipherDirection {
    fn from(direction: tc_stream_cipher::CipherDirection) -> Self {
        match direction {
            tc_stream_cipher::CipherDirection::Encrypt => Self::Encrypt,
            tc_stream_cipher::CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}

impl From<CipherDirection> for tc_stream_cipher::CipherDirection {
    fn from(direction: CipherDirection) -> Self {
        match direction {
            CipherDirection::Encrypt => Self::Encrypt,
            CipherDirection::Decrypt => Self::Decrypt,
        }
    }
}
