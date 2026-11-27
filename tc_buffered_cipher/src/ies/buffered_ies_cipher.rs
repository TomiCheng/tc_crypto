use alloc::vec::Vec;
use core::error::Error;

use tc_agreement::{Agreement, AgreementInit};
use tc_block_cipher::KeyRef;
use tc_block_modes::KeyWithIvRef;
use tc_kdf::kdf::KdfParamsRef;
use tc_kdf::{Kdf, KdfInit};
use tc_macs::{Mac, MacInit};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::ies::{
    IesCipherEngine, IesCipherParams, IesEngine, IesError, IesInitParamsRef, IesParams,
};
use crate::{BufferedCipher, BufferedCipherInit, CipherDirection};

/// Bouncy Castle's `BufferedIesCipher`: an [`IesEngine`] or an [`IesCipherEngine`] behind
/// [`BufferedCipher`]. The engine takes a whole message, so the input waits in a buffer until
/// `do_final`, which hands it to the engine and writes the result; `process_bytes` writes
/// nothing. The buffer is wiped on `do_final`, `reset` and drop.
///
/// It is initialized with an [`IesInitParamsRef`] of this party's private key, the other party's
/// public key and the IES parameters. The engine keeps the shared secret between messages, so
/// `do_final` and `reset` leave it ready for the next message under the same keys.
///
/// Constant time when the engine it wraps is; lengths are public.
pub struct BufferedIesCipher<E> {
    engine: E,
    initialized: bool,
    buffer: Zeroizing<Vec<u8>>,
}

impl<E> BufferedIesCipher<E> {
    /// An adapter over `engine`, not yet initialized. Constant time.
    pub fn new(engine: E) -> Self {
        Self {
            engine,
            initialized: false,
            buffer: Zeroizing::new(Vec::new()),
        }
    }

    fn check_initialized(&self) -> Result<(), IesError> {
        if self.initialized {
            Ok(())
        } else {
            Err(IesError::NotInitialised)
        }
    }

    fn buffered_len(&self, input_len: usize) -> Result<usize, IesError> {
        self.buffer
            .len()
            .checked_add(input_len)
            .ok_or(IesError::LengthOverflow)
    }

    fn finish(
        &mut self,
        output: &mut [u8],
        process: impl FnOnce(&mut E, &[u8]) -> Result<Vec<u8>, IesError>,
    ) -> Result<usize, IesError> {
        let result = process(&mut self.engine, &self.buffer);
        self.buffer.zeroize();
        let result = Zeroizing::new(result?);
        let written = result.len();
        output
            .get_mut(..written)
            .ok_or(IesError::OutputTooShort)?
            .copy_from_slice(&result);
        Ok(written)
    }
}

macro_rules! buffered_ies {
    ($engine:ty, [$($generic:ident),*], $params:ident, where $($bounds:tt)*) => {
        impl<$($generic),*, Priv, P> BufferedCipherInit<
            IesInitParamsRef<'_, Priv, <A as Agreement>::PublicKey, P>,
        > for BufferedIesCipher<$engine>
        where
            A: Agreement + AgreementInit<Priv>,
            Priv: ?Sized,
            P: $params + ?Sized,
            <A as Agreement>::Error: Error + Send + Sync + 'static,
            <A as AgreementInit<Priv>>::Error: Error + Send + Sync + 'static,
            $($bounds)*
        {
            type Error = IesError;

            /// Discards any buffered input and initializes the engine in `direction` with the
            /// keys and parameters of `params`. A failure leaves the adapter uninitialized.
            /// Constant time with respect to the private key when the agreement is.
            fn init(
                &mut self,
                direction: CipherDirection,
                params: &IesInitParamsRef<'_, Priv, <A as Agreement>::PublicKey, P>,
            ) -> Result<(), IesError> {
                self.initialized = false;
                self.buffer.zeroize();
                self.engine.init(
                    direction,
                    params.private_key(),
                    params.public_key(),
                    params.params(),
                )?;
                self.initialized = true;
                Ok(())
            }
        }

        impl<$($generic),*> BufferedCipher for BufferedIesCipher<$engine>
        where
            $($bounds)*
        {
            type Error = IesError;

            /// Zero, as in Bouncy Castle: IES is not a block cipher. Constant time.
            fn block_size(&self) -> usize {
                0
            }

            /// Zero, since the output comes only from `do_final`. Fails before `init`.
            /// Constant time.
            fn update_output_len(&self, _input_len: usize) -> Result<usize, IesError> {
                self.check_initialized()?;
                Ok(0)
            }

            /// The engine's output length for the buffered input and `input_len` more bytes: the
            /// message and the MAC on encryption, an upper bound of the message on decryption.
            /// Fails before `init` and when the length overflows. Constant time.
            fn output_len(&self, input_len: usize) -> Result<usize, IesError> {
                self.check_initialized()?;
                self.engine.output_len(self.buffered_len(input_len)?)
            }

            /// Appends `input` to the buffer and writes nothing. Fails before `init` and when
            /// the length overflows. Constant time.
            fn process_bytes(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, IesError> {
                self.check_initialized()?;
                self.buffered_len(input.len())?;
                self.buffer.extend_from_slice(input);
                Ok(0)
            }

            /// Hands the buffered message to the engine, wipes the buffer and writes the result:
            /// `C || T` on encryption, the message on decryption once the MAC matches. `output`
            /// must hold `output_len(0)` bytes. On failure nothing is written. Constant time
            /// when the engine is.
            fn do_final(&mut self, output: &mut [u8]) -> Result<usize, IesError> {
                if output.len() < self.output_len(0)? {
                    return Err(IesError::OutputTooShort);
                }
                self.finish(output, |engine, message| engine.process_block(message))
            }

            /// Wipes the buffered input; the engine keeps its keys for the next message.
            /// Constant time.
            fn reset(&mut self) {
                self.buffer.zeroize();
            }
        }
    };
}

buffered_ies!(IesEngine<A, K, M>, [A, K, M, KI, MI], IesParams, where
    K: Kdf + for<'a> KdfInit<KdfParamsRef<'a>, Error = KI>,
    <K as Kdf>::Error: Error + Send + Sync + 'static,
    KI: Error + Send + Sync + 'static,
    M: Mac + for<'a> MacInit<KeyRef<'a>, Error = MI>,
    <M as Mac>::Error: Error + Send + Sync + 'static,
    MI: Error + Send + Sync + 'static,
);

buffered_ies!(IesCipherEngine<A, K, M, C>, [A, K, M, C, KI, MI, CV], IesCipherParams, where
    K: Kdf + for<'a> KdfInit<KdfParamsRef<'a>, Error = KI>,
    <K as Kdf>::Error: Error + Send + Sync + 'static,
    KI: Error + Send + Sync + 'static,
    M: Mac + for<'a> MacInit<KeyRef<'a>, Error = MI>,
    <M as Mac>::Error: Error + Send + Sync + 'static,
    MI: Error + Send + Sync + 'static,
    C: BufferedCipher + for<'a> BufferedCipherInit<KeyWithIvRef<'a>, Error = CV>,
    <C as BufferedCipher>::Error: Error + Send + Sync + 'static,
    CV: Error + Send + Sync + 'static,
);
