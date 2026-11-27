use crate::ies::{IesCipherParams, IesParams};

/// Borrowed [`IesParams`]; nothing is checked here, each length is checked by the engine.
/// Constant time: it only holds borrowed values.
#[derive(Clone, Copy, Debug)]
pub struct IesParamsRef<'a> {
    derivation_v: &'a [u8],
    encoding_v: &'a [u8],
    mac_key_bits: usize,
}

impl<'a> IesParamsRef<'a> {
    /// As BC's `IesParameters(derivation, encoding, macKeySize)`. Constant time.
    pub const fn new(derivation_v: &'a [u8], encoding_v: &'a [u8], mac_key_bits: usize) -> Self {
        Self {
            derivation_v,
            encoding_v,
            mac_key_bits,
        }
    }
}

impl IesParams for IesParamsRef<'_> {
    /// Constant time: returns the slice without reading it.
    fn derivation_v(&self) -> &[u8] {
        self.derivation_v
    }

    /// Constant time: returns the slice without reading it.
    fn encoding_v(&self) -> &[u8] {
        self.encoding_v
    }

    /// Constant time.
    fn mac_key_bits(&self) -> usize {
        self.mac_key_bits
    }
}

/// Borrowed [`IesCipherParams`]; nothing is checked here, each length is checked by the engine.
/// Constant time: it only holds borrowed values.
///
#[derive(Clone, Copy, Debug)]
pub struct IesCipherParamsRef<'a> {
    ies: IesParamsRef<'a>,
    cipher_key_bits: usize,
    iv: &'a [u8],
}
impl<'a> IesCipherParamsRef<'a> {
    /// As BC's `IesWithCipherParameters(derivation, encoding, macKeySize, cipherKeySize)`,
    /// without an IV. Constant time.
    pub const fn new(
        derivation_v: &'a [u8],
        encoding_v: &'a [u8],
        mac_key_bits: usize,
        cipher_key_bits: usize,
    ) -> Self {
        Self {
            ies: IesParamsRef::new(derivation_v, encoding_v, mac_key_bits),
            cipher_key_bits,
            iv: &[],
        }
    }

    /// The same parameters with `iv` for the cipher, as BC's `ParametersWithIV` around them.
    /// Constant time.
    pub const fn with_iv(self, iv: &'a [u8]) -> Self {
        Self { iv, ..self }
    }
}
impl IesParams for IesCipherParamsRef<'_> {
    /// Constant time: returns the slice without reading it.
    fn derivation_v(&self) -> &[u8] {
        self.ies.derivation_v
    }

    /// Constant time: returns the slice without reading it.
    fn encoding_v(&self) -> &[u8] {
        self.ies.encoding_v
    }

    /// Constant time.
    fn mac_key_bits(&self) -> usize {
        self.ies.mac_key_bits
    }
}
impl IesCipherParams for IesCipherParamsRef<'_> {
    /// Constant time.
    fn cipher_key_bits(&self) -> usize {
        self.cipher_key_bits
    }

    /// Constant time: returns the slice without reading it.
    fn iv(&self) -> &[u8] {
        self.iv
    }
}
