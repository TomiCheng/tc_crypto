use alloc::vec::Vec;
use core::error::Error;

use tc_agreement::{Agreement, AgreementInit};
use tc_block_cipher::KeyRef;

use crate::CipherDirection;
use tc_constant_time::fixed_time_eq;
use tc_kdf::kdf::KdfParamsRef;
use tc_kdf::{Kdf, KdfInit};
use tc_macs::{Mac, MacInit};
use tc_zeroize::Zeroizing;

use crate::ies::steps::{derive_keys, key_len, shared_secret, tag};
use crate::ies::{IesError, IesParams};

struct Session {
    direction: CipherDirection,
    z: Zeroizing<Vec<u8>>,
    derivation_v: Vec<u8>,
    encoding_v: Vec<u8>,
    mac_key_len: usize,
}

/// IES with XOR encryption, BC C#'s `IesEngine` built without a cipher: the agreement gives
/// `Z`, the KDF stretches it into the MAC key `K2` followed by a keystream `K1` as long as the
/// message, and the output is `C || T` with `C = M xor K1` and `T = MAC(K2, C || encoding V)`.
///
/// As in BC C#, both parties' keys are static: no ephemeral public key is generated or sent.
/// `K2` comes before `K1`, as BC now orders them, so that a keystream known from one message
/// never covers the MAC key of another.
///
/// Constant time when the agreement, KDF and MAC it wraps are; lengths are public.
pub struct IesEngine<A, K, M> {
    agreement: A,
    kdf: K,
    mac: M,
    session: Option<Session>,
}

impl<A, K, M> IesEngine<A, K, M> {
    /// An engine over `agreement`, `kdf` and `mac`, not yet initialized. Constant time.
    pub const fn new(agreement: A, kdf: K, mac: M) -> Self {
        Self {
            agreement,
            kdf,
            mac,
            session: None,
        }
    }
}

impl<A: Agreement, K, M> IesEngine<A, K, M> {
    /// Agrees on `Z` from `private_key` and the other party's `public_key` and keeps it, with
    /// copies of the parameters, for the messages that follow. A failure leaves the engine
    /// uninitialized. Constant time with respect to the private key when the agreement is.
    pub fn init<Priv, P>(
        &mut self,
        direction: CipherDirection,
        private_key: &Priv,
        public_key: &A::PublicKey,
        params: &P,
    ) -> Result<(), IesError>
    where
        A: AgreementInit<Priv>,
        Priv: ?Sized,
        P: IesParams + ?Sized,
        <A as Agreement>::Error: Error + Send + Sync + 'static,
        <A as AgreementInit<Priv>>::Error: Error + Send + Sync + 'static,
    {
        self.session = None;
        let mac_key_len = key_len(params.mac_key_bits())?;
        let z = shared_secret(&mut self.agreement, private_key, public_key)?;
        self.session = Some(Session {
            direction,
            z,
            derivation_v: params.derivation_v().to_vec(),
            encoding_v: params.encoding_v().to_vec(),
            mac_key_len,
        });
        Ok(())
    }
}

impl<A, K, M, KI, MI> IesEngine<A, K, M>
where
    K: Kdf + for<'a> KdfInit<KdfParamsRef<'a>, Error = KI>,
    <K as Kdf>::Error: Error + Send + Sync + 'static,
    KI: Error + Send + Sync + 'static,
    M: Mac + for<'a> MacInit<KeyRef<'a>, Error = MI>,
    <M as Mac>::Error: Error + Send + Sync + 'static,
    MI: Error + Send + Sync + 'static,
{
    /// Encrypts `input` into `C || T`, or checks and decrypts `C || T`, as `init` chose. The
    /// MAC is compared without stopping at the first difference, and on decryption it is
    /// checked before any plaintext is formed. Constant time with respect to the keys and the
    /// message when the KDF and MAC are; the message length is public.
    pub fn process_block(&mut self, input: &[u8]) -> Result<Vec<u8>, IesError> {
        let session = self.session.as_ref().ok_or(IesError::NotInitialised)?;
        let mac_key_len = session.mac_key_len;
        match session.direction {
            CipherDirection::Encrypt => {
                let keys = derive_keys(
                    &mut self.kdf,
                    &session.z,
                    &session.derivation_v,
                    mac_key_len + input.len(),
                )?;
                let (k2, k1) = keys.split_at(mac_key_len);
                let mut output: Vec<u8> = input.iter().zip(k1).map(|(m, k)| m ^ k).collect();
                let tag = tag(&mut self.mac, k2, &output, &session.encoding_v)?;
                output.extend_from_slice(&tag);
                Ok(output)
            }
            CipherDirection::Decrypt => {
                let mac_size = self.mac.mac_size();
                let body_len = input
                    .len()
                    .checked_sub(mac_size)
                    .ok_or(IesError::InputTooShort)?;
                let (ciphertext, received) = input.split_at(body_len);
                let keys = derive_keys(
                    &mut self.kdf,
                    &session.z,
                    &session.derivation_v,
                    mac_key_len + body_len,
                )?;
                let (k2, k1) = keys.split_at(mac_key_len);
                let expected = tag(&mut self.mac, k2, ciphertext, &session.encoding_v)?;
                if !fixed_time_eq(received, &expected) {
                    return Err(IesError::InvalidMac);
                }
                Ok(ciphertext.iter().zip(k1).map(|(c, k)| c ^ k).collect())
            }
        }
    }
}
