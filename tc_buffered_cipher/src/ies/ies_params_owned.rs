use alloc::vec::Vec;

use crate::ies::{IesCipherParams, IesParams};

/// Owned [`IesParams`], for parameters that outlive the buffers they came from; nothing is
/// checked here, each length is checked by the engine. The vectors are public, so they are not
/// wiped. Constant time: it only holds the values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IesParamsOwned {
    derivation_v: Vec<u8>,
    encoding_v: Vec<u8>,
    mac_key_bits: usize,
}

impl IesParamsOwned {
    /// As BC's `IesParameters(derivation, encoding, macKeySize)`, taking the vectors without
    /// copying them. Constant time.
    pub const fn new(derivation_v: Vec<u8>, encoding_v: Vec<u8>, mac_key_bits: usize) -> Self {
        Self {
            derivation_v,
            encoding_v,
            mac_key_bits,
        }
    }
}

impl IesParams for IesParamsOwned {
    /// Constant time: returns the slice without reading it.
    fn derivation_v(&self) -> &[u8] {
        &self.derivation_v
    }

    /// Constant time: returns the slice without reading it.
    fn encoding_v(&self) -> &[u8] {
        &self.encoding_v
    }

    /// Constant time.
    fn mac_key_bits(&self) -> usize {
        self.mac_key_bits
    }
}

/// Owned [`IesCipherParams`], for parameters that outlive the buffers they came from; nothing is
/// checked here, each length is checked by the engine. The vectors and the IV are public, so
/// they are not wiped. Constant time: it only holds the values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IesCipherParamsOwned {
    ies: IesParamsOwned,
    cipher_key_bits: usize,
    iv: Vec<u8>,
}

impl IesCipherParamsOwned {
    /// As BC's `IesWithCipherParameters(derivation, encoding, macKeySize, cipherKeySize)`,
    /// without an IV, taking the vectors without copying them. Constant time.
    pub const fn new(
        derivation_v: Vec<u8>,
        encoding_v: Vec<u8>,
        mac_key_bits: usize,
        cipher_key_bits: usize,
    ) -> Self {
        Self {
            ies: IesParamsOwned::new(derivation_v, encoding_v, mac_key_bits),
            cipher_key_bits,
            iv: Vec::new(),
        }
    }

    /// The same parameters with `iv` for the cipher, as BC's `ParametersWithIV` around them.
    /// Constant time.
    pub fn with_iv(self, iv: Vec<u8>) -> Self {
        Self { iv, ..self }
    }
}

impl IesParams for IesCipherParamsOwned {
    /// Constant time: returns the slice without reading it.
    fn derivation_v(&self) -> &[u8] {
        self.ies.derivation_v()
    }

    /// Constant time: returns the slice without reading it.
    fn encoding_v(&self) -> &[u8] {
        self.ies.encoding_v()
    }

    /// Constant time.
    fn mac_key_bits(&self) -> usize {
        self.ies.mac_key_bits()
    }
}

impl IesCipherParams for IesCipherParamsOwned {
    /// Constant time.
    fn cipher_key_bits(&self) -> usize {
        self.cipher_key_bits
    }

    /// Constant time: returns the slice without reading it.
    fn iv(&self) -> &[u8] {
        &self.iv
    }
}
