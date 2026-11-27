/// The parameters of IES with XOR encryption, BC's `IesParameters`.
pub trait IesParams {
    /// The derivation vector, given to the KDF as its IV; empty when there is none.
    fn derivation_v(&self) -> &[u8];

    /// The encoding vector, MACed after the ciphertext; empty when there is none.
    fn encoding_v(&self) -> &[u8];

    /// The length of the MAC key `K2` in bits, BC's `MacKeySize`.
    fn mac_key_bits(&self) -> usize;
}

/// The parameters of IES with a block cipher, BC's `IesWithCipherParameters`, optionally
/// wrapped in `ParametersWithIV`.
pub trait IesCipherParams: IesParams {
    /// The length of the cipher key `K1` in bits, BC's `CipherKeySize`.
    fn cipher_key_bits(&self) -> usize;

    /// The IV given to the cipher with `K1`; empty when there is none. A mode that needs an IV,
    /// such as CBC, refuses an empty one, where BC's CBC falls back to zeros: give it a zero IV
    /// to match BC.
    fn iv(&self) -> &[u8];
}
