use core::fmt;

/// An error creating, reseeding or drawing from a DRBG.
///
/// Every variant carries only public values: lengths, sizes and strengths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrbgError {
    /// The digest or MAC output size is not one of the SHA family sizes
    /// SP 800-90A supports: 20, 28, 32, 48 or 64 bytes.
    UnsupportedOutputSize(usize),
    /// The requested security strength, in bits, exceeds what the primitive
    /// provides.
    UnsupportedSecurityStrength {
        /// The requested strength in bits.
        requested: usize,
        /// The highest strength the primitive provides, in bits.
        maximum: usize,
    },
    /// The entropy read per seeding, in bytes, is shorter than the security
    /// strength.
    InsufficientEntropy {
        /// The fewest bytes the security strength needs.
        required: usize,
        /// The bytes asked for.
        provided: usize,
    },
    /// The entropy read per seeding, in bytes, exceeds what the generator
    /// buffers.
    ExcessiveEntropy {
        /// The most bytes the generator buffers.
        maximum: usize,
        /// The bytes asked for.
        provided: usize,
    },
    /// CTR_DRBG takes only AES-128, AES-192 or AES-256 key sizes, in bits.
    InvalidKeySize(usize),
    /// CTR_DRBG takes only a block cipher with 16-byte blocks.
    InvalidBlockSize(usize),
    /// Without a derivation function, the seed material must be exactly
    /// seedlen bytes.
    InvalidSeedLength {
        /// The seedlen of the generator, in bytes.
        expected: usize,
        /// The length of the seed material given.
        actual: usize,
    },
    /// One request asks for more than SP 800-90A allows, 32 KiB.
    RequestTooLarge {
        /// The bytes asked for.
        requested: usize,
        /// The most one request may ask for.
        maximum: usize,
    },
    /// 2^47 requests have been made since the last seeding; call
    /// `Drbg::reseed`.
    ReseedRequired,
    /// The MAC failed to initialize or to process its input.
    MacFailure,
    /// The block cipher failed to initialize or to process a block.
    CipherFailure,
    /// An input is too long for the 32-bit length fields SP 800-90A specifies.
    InputTooLong,
}

impl fmt::Display for DrbgError {
    /// Writes a description with the public values the error carries.
    /// Constant time with respect to the generator's secrets, which no error
    /// holds.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOutputSize(size) => {
                write!(formatter, "unsupported DRBG output size: {size} bytes")
            }
            Self::UnsupportedSecurityStrength { requested, maximum } => write!(
                formatter,
                "requested DRBG security strength {requested} exceeds maximum {maximum}"
            ),
            Self::InsufficientEntropy { required, provided } => write!(
                formatter,
                "DRBG entropy is too short: required {required} bytes, provided {provided}"
            ),
            Self::ExcessiveEntropy { maximum, provided } => write!(
                formatter,
                "DRBG entropy is too long: maximum {maximum} bytes, provided {provided}"
            ),
            Self::InvalidKeySize(size) => {
                write!(formatter, "invalid CTR_DRBG AES key size: {size} bits")
            }
            Self::InvalidBlockSize(size) => {
                write!(formatter, "invalid CTR_DRBG block size: {size} bytes")
            }
            Self::InvalidSeedLength { expected, actual } => write!(
                formatter,
                "invalid CTR_DRBG seed length: expected {expected} bytes, got {actual}"
            ),
            Self::RequestTooLarge { requested, maximum } => write!(
                formatter,
                "DRBG request is too large: requested {requested} bytes, maximum {maximum}"
            ),
            Self::ReseedRequired => formatter.write_str("DRBG reseed is required"),
            Self::MacFailure => formatter.write_str("DRBG MAC operation failed"),
            Self::CipherFailure => formatter.write_str("DRBG block-cipher operation failed"),
            Self::InputTooLong => formatter.write_str("DRBG input is too long"),
        }
    }
}

impl core::error::Error for DrbgError {}
