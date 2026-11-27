use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::error::Error;

use tc_agreement::{Agreement, AgreementInit};
use tc_block_cipher::KeyRef;

use crate::CipherDirection;
use crate::{BufferedCipher, BufferedCipherInit};
use tc_block_modes::KeyWithIvRef;
use tc_constant_time::fixed_time_eq;
use tc_kdf::kdf::KdfParamsRef;
use tc_kdf::{Kdf, KdfInit};
use tc_macs::{Mac, MacInit};
use tc_zeroize::Zeroizing;

use crate::ies::steps::{derive_keys, key_len, shared_secret, tag};
use crate::ies::{IesCipherParams, IesError};

struct Session {
    direction: CipherDirection,
    z: Zeroizing<Vec<u8>>,
    derivation_v: Vec<u8>,
    encoding_v: Vec<u8>,
    cipher_key_len: usize,
    mac_key_len: usize,
    iv: Vec<u8>,
}

/// IES with a block cipher, BC C#'s `IesEngine` built with a `BufferedBlockCipher`. Available
/// with the `cipher` feature.
///
/// The agreement gives `Z`, the KDF stretches it into the cipher key `K1` followed by the MAC
/// key `K2`, and the output is `C || T` with `C` the cipher's encryption of the message under
/// `K1` and the IV, if any, and `T = MAC(K2, C || encoding V)`. As in BC C#, both parties' keys
/// are static: no ephemeral public key is generated or sent.
///
/// Constant time when the agreement, KDF, MAC and cipher it wraps are; lengths are public.
pub struct IesCipherEngine<A, K, M, C> {
    agreement: A,
    kdf: K,
    mac: M,
    cipher: C,
    session: Option<Session>,
}

impl<A, K, M, C> IesCipherEngine<A, K, M, C> {
    /// An engine over `agreement`, `kdf`, `mac` and `cipher`, not yet initialized.
    /// Constant time.
    pub const fn new(agreement: A, kdf: K, mac: M, cipher: C) -> Self {
        Self {
            agreement,
            kdf,
            mac,
            cipher,
            session: None,
        }
    }
}

impl<A: Agreement, K, M, C> IesCipherEngine<A, K, M, C> {
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
        P: IesCipherParams + ?Sized,
        <A as Agreement>::Error: Error + Send + Sync + 'static,
        <A as AgreementInit<Priv>>::Error: Error + Send + Sync + 'static,
    {
        self.session = None;
        let cipher_key_len = key_len(params.cipher_key_bits())?;
        let mac_key_len = key_len(params.mac_key_bits())?;
        let z = shared_secret(&mut self.agreement, private_key, public_key)?;
        self.session = Some(Session {
            direction,
            z,
            derivation_v: params.derivation_v().to_vec(),
            encoding_v: params.encoding_v().to_vec(),
            cipher_key_len,
            mac_key_len,
            iv: params.iv().to_vec(),
        });
        Ok(())
    }
}

impl<A, K, M, C, KI, MI, CV> IesCipherEngine<A, K, M, C>
where
    K: Kdf + for<'a> KdfInit<KdfParamsRef<'a>, Error = KI>,
    <K as Kdf>::Error: Error + Send + Sync + 'static,
    KI: Error + Send + Sync + 'static,
    M: Mac + for<'a> MacInit<KeyRef<'a>, Error = MI>,
    <M as Mac>::Error: Error + Send + Sync + 'static,
    MI: Error + Send + Sync + 'static,
    C: BufferedCipher + for<'a> BufferedCipherInit<KeyWithIvRef<'a>, Error = CV>,
    <C as BufferedCipher>::Error: Error + Send + Sync + 'static,
    CV: Error + Send + Sync + 'static,
{
    /// Encrypts `input` into `C || T`, or checks and decrypts `C || T`, as `init` chose. On
    /// decryption the MAC is compared, without stopping at the first difference, before the
    /// cipher's final block, so that a padding failure cannot be told apart from a forged
    /// message; the partial plaintext is wiped when the MAC does not match. Constant time with
    /// respect to the keys and the message when the KDF, MAC and cipher are; the message length
    /// is public.
    pub fn process_block(&mut self, input: &[u8]) -> Result<Vec<u8>, IesError> {
        let session = self.session.as_ref().ok_or(IesError::NotInitialised)?;
        let keys = |kdf: &mut K, len| derive_keys(kdf, &session.z, &session.derivation_v, len);
        let cipher_error = |error: <C as BufferedCipher>::Error| IesError::Cipher(Box::new(error));
        match session.direction {
            CipherDirection::Encrypt => {
                let keys = keys(&mut self.kdf, session.cipher_key_len + session.mac_key_len)?;
                let (k1, k2) = keys.split_at(session.cipher_key_len);
                init_cipher(&mut self.cipher, CipherDirection::Encrypt, k1, &session.iv)?;
                let mut output =
                    vec![0; self.cipher.output_len(input.len()).map_err(cipher_error)?];
                let mut len = self
                    .cipher
                    .process_bytes(input, &mut output)
                    .map_err(cipher_error)?;
                len += self
                    .cipher
                    .do_final(&mut output[len..])
                    .map_err(cipher_error)?;
                output.truncate(len);
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
                let keys = keys(&mut self.kdf, session.cipher_key_len + session.mac_key_len)?;
                let (k1, k2) = keys.split_at(session.cipher_key_len);
                init_cipher(&mut self.cipher, CipherDirection::Decrypt, k1, &session.iv)?;
                let mut plaintext = Zeroizing::new(vec![
                    0;
                    self.cipher
                        .output_len(body_len)
                        .map_err(cipher_error)?
                ]);
                let mut len = self
                    .cipher
                    .process_bytes(ciphertext, &mut plaintext)
                    .map_err(cipher_error)?;
                let expected = tag(&mut self.mac, k2, ciphertext, &session.encoding_v)?;
                if !fixed_time_eq(received, &expected) {
                    return Err(IesError::InvalidMac);
                }
                len += self
                    .cipher
                    .do_final(&mut plaintext[len..])
                    .map_err(cipher_error)?;
                Ok(plaintext[..len].to_vec())
            }
        }
    }
}

/// Gives the cipher `K1` with the IV, which may be empty. Modes without an IV, such as ECB,
/// ignore it; modes that need one, such as CBC, refuse an empty IV where BC's CBC falls back
/// to zeros.
fn init_cipher<C, CV>(
    cipher: &mut C,
    direction: CipherDirection,
    k1: &[u8],
    iv: &[u8],
) -> Result<(), IesError>
where
    C: for<'a> BufferedCipherInit<KeyWithIvRef<'a>, Error = CV>,
    CV: Error + Send + Sync + 'static,
{
    cipher
        .init(direction, &KeyWithIvRef::new(k1, iv))
        .map_err(|error| IesError::Cipher(Box::new(error)))
}
