//! The steps the two engines share: agreement, key derivation and the MAC.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::error::Error;

use tc_agreement::{Agreement, AgreementInit};
use tc_block_cipher::KeyRef;
use tc_kdf::kdf::KdfParamsRef;
use tc_kdf::{Kdf, KdfInit};
use tc_macs::{Mac, MacInit};
use tc_zeroize::Zeroizing;

use crate::ies::IesError;

/// `bits / 8`, refusing a length that is not a whole number of bytes. Constant time.
pub(crate) fn key_len(bits: usize) -> Result<usize, IesError> {
    if bits % 8 == 0 {
        Ok(bits / 8)
    } else {
        Err(IesError::InvalidKeyLength(bits))
    }
}

/// The shared secret `Z`, padded to the agreement's size as BC's
/// `BigIntegers.AsUnsignedByteArray(GetFieldSize(), z)`. Constant time when the agreement is.
pub(crate) fn shared_secret<A, Priv>(
    agreement: &mut A,
    private_key: &Priv,
    public_key: &A::PublicKey,
) -> Result<Zeroizing<Vec<u8>>, IesError>
where
    A: Agreement + AgreementInit<Priv>,
    Priv: ?Sized,
    <A as Agreement>::Error: Error + Send + Sync + 'static,
    <A as AgreementInit<Priv>>::Error: Error + Send + Sync + 'static,
{
    agreement
        .init(private_key)
        .map_err(|error| IesError::Agreement(Box::new(error)))?;
    let mut z = Zeroizing::new(vec![0; agreement.agreement_size()]);
    agreement
        .calculate_agreement(public_key, &mut z)
        .map_err(|error| IesError::Agreement(Box::new(error)))?;
    Ok(z)
}

/// `len` bytes of `KDF(Z, derivation V)`, the KDF initialized afresh as BC does on every
/// message. Constant time when the KDF is.
pub(crate) fn derive_keys<K, KI>(
    kdf: &mut K,
    z: &[u8],
    derivation_v: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, IesError>
where
    K: Kdf + for<'a> KdfInit<KdfParamsRef<'a>, Error = KI>,
    <K as Kdf>::Error: Error + Send + Sync + 'static,
    KI: Error + Send + Sync + 'static,
{
    kdf.init(&KdfParamsRef::with_iv(z, derivation_v))
        .map_err(|error| IesError::Kdf(Box::new(error)))?;
    let mut keys = Zeroizing::new(vec![0; len]);
    kdf.generate_bytes(&mut keys)
        .map_err(|error| IesError::Kdf(Box::new(error)))?;
    Ok(keys)
}

/// `MAC(K2, ciphertext || encoding V)`. BC also appends a length tag of the encoding V when an
/// ephemeral `V` is present, which the static-key form never has. Constant time when the MAC
/// is.
pub(crate) fn tag<M, MI>(
    mac: &mut M,
    k2: &[u8],
    ciphertext: &[u8],
    encoding_v: &[u8],
) -> Result<Vec<u8>, IesError>
where
    M: Mac + for<'a> MacInit<KeyRef<'a>, Error = MI>,
    <M as Mac>::Error: Error + Send + Sync + 'static,
    MI: Error + Send + Sync + 'static,
{
    let mac_error = |error: <M as Mac>::Error| IesError::Mac(Box::new(error));
    mac.init(&KeyRef::new(k2))
        .map_err(|error| IesError::Mac(Box::new(error)))?;
    mac.update(ciphertext).map_err(mac_error)?;
    mac.update(encoding_v).map_err(mac_error)?;
    let mut tag = vec![0; mac.mac_size()];
    mac.do_final(&mut tag).map_err(mac_error)?;
    Ok(tag)
}
