mod sealed {
    pub trait Sealed {}
}

/// The chaining under CTS, [`Ecb`] or [`Cbc`], which decides whether `init` takes an IV.
///
/// Sealed: no other chaining can be added outside this crate.
pub trait CtsChaining: sealed::Sealed {
    #[doc(hidden)]
    const CBC: bool;
}

/// No chaining, as Bouncy Castle's `CtsBlockCipher` built over an `EcbBlockCipher`. The
/// parameters of `init` go to the block cipher as they are.
pub struct Ecb;

/// CBC chaining, as Bouncy Castle's `CtsBlockCipher` built over a `CbcBlockCipher`. Beyond one
/// block it is the CBC-CTS of RFC 3962, CS3 of the addendum to NIST SP 800-38A; for exactly one
/// block Bouncy Castle encrypts the encrypted block once more, and so does this. The parameters
/// of `init` carry an IV of one block.
pub struct Cbc;

impl sealed::Sealed for Ecb {}
impl sealed::Sealed for Cbc {}

impl CtsChaining for Ecb {
    const CBC: bool = false;
}

impl CtsChaining for Cbc {
    const CBC: bool = true;
}
