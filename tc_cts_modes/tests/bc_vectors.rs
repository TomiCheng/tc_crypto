//! `FixedCtsBlockCipher` and `CtsBlockCipher`: the three vectors of Bouncy Castle's `CTSTest`
//! (DES ECB, DES CBC and Skipjack CBC), the AES-128 CBC-CTS of RFC 3962 appendix B, the AES
//! ECB-CTS and single block Bouncy Castle gives, RC2 CBC-CTS from OpenSSL, input in pieces, and
//! the errors.

use tc_aes::AesEngine;
use tc_block_cipher::{KeyParams, KeyRef};
use tc_block_modes::{BlockModeInitError, IvParams, KeyWithIvRef};
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
#[cfg(feature = "alloc")]
use tc_cts_modes::CtsBlockCipher;
use tc_cts_modes::{Cbc, Ecb, FixedCtsBlockCipher};
use tc_des::DesEngine;
use tc_misc_block_cipher::skipjack::SkipjackEngine;
use tc_rc_cipher::{Rc2Engine, Rc2Params, Rc2ParamsRef};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Feeds the whole message at once.
fn run<B, P>(cipher: &mut B, direction: CipherDirection, params: &P, input: &[u8]) -> Vec<u8>
where
    B: BufferedCipher + BufferedCipherInit<P>,
    <B as BufferedCipher>::Error: core::fmt::Debug,
    <B as BufferedCipherInit<P>>::Error: core::fmt::Debug,
    P: ?Sized,
{
    cipher.init(direction, params).unwrap();
    let mut output = vec![0; cipher.output_len(input.len()).unwrap()];
    let mut written = cipher.process_bytes(input, &mut output).unwrap();
    written += cipher.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

/// Encrypts to `expected`, then decrypts back to `plaintext`.
fn round_trip<B, P>(cipher: &mut B, params: &P, plaintext: &[u8], expected: &[u8])
where
    B: BufferedCipher + BufferedCipherInit<P>,
    <B as BufferedCipher>::Error: core::fmt::Debug,
    <B as BufferedCipherInit<P>>::Error: core::fmt::Debug,
    P: ?Sized,
{
    let sealed = run(cipher, CipherDirection::Encrypt, params, plaintext);
    assert_eq!(sealed, expected, "ciphertext of {} bytes", plaintext.len());
    let opened = run(cipher, CipherDirection::Decrypt, params, &sealed);
    assert_eq!(opened, plaintext);
}

const DES_KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const SKIPJACK_KEY: [u8; 10] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xee, 0xff];
const BC_IV: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

#[test]
fn the_three_cts_test_vectors_match_bouncy_castle() {
    let in1 = bytes("4e6f7720697320746865207420");
    let in2 = bytes("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f0aaa");

    let mut ecb = FixedCtsBlockCipher::<_, 8, Ecb>::ecb(DesEngine::new());
    round_trip(
        &mut ecb,
        &KeyRef::new(&DES_KEY),
        &in1,
        &bytes("9952f131588465033fa40e8a98"),
    );
    let mut cbc = FixedCtsBlockCipher::<_, 8, Cbc>::cbc(DesEngine::new());
    round_trip(
        &mut cbc,
        &KeyWithIvRef::new(&DES_KEY, &BC_IV),
        &in1,
        &bytes("358f84d01eb42988dc34efb994"),
    );
    let mut skipjack = FixedCtsBlockCipher::<_, 8, Cbc>::cbc(SkipjackEngine::new());
    round_trip(
        &mut skipjack,
        &KeyWithIvRef::new(&SKIPJACK_KEY, &BC_IV),
        &in2,
        &bytes("170171cfad3f04530c509b0c1f0be0aefbd45a8e3755a873bff5ea198504b71683c6"),
    );
}

const RFC_3962_KEY: &str = "636869636b656e207465726979616b69";
const RFC_3962_MESSAGE: &str = "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e64207769746820626f74746f6d6c657373";

/// RFC 3962 appendix B, with an IV of zeros, and what Bouncy Castle gives for exactly one block.
const AES_CBC: [(usize, &str); 7] = [
    (16, "e7664c13ff28c965b0d2a0e7ec353706"),
    (17, "c6353568f2bf8cb4d8a580362da7ff7f97"),
    (
        31,
        "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
    ),
    (
        32,
        "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
    ),
    (
        47,
        "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
    ),
    (
        48,
        "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
    ),
    (
        64,
        "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8426cff30b100ed348cf882311b3266069dad8bbb96c4cdc03bc103e1a194bbd8",
    ),
];

/// As Bouncy Castle computes it over an `EcbBlockCipher`.
const AES_ECB: [(usize, &str); 3] = [
    (
        47,
        "97687268d6ecccc0c07b25e25ecfe5842f0f4df59a97fd3fb99cbd0c0786a184230c15eacecdc08fc1e2b658760fff",
    ),
    (
        48,
        "97687268d6ecccc0c07b25e25ecfe58451c086ba29c911ae3014cbd852270a87230c15eacecdc08fc1e2b658760fff8a",
    ),
    (
        64,
        "97687268d6ecccc0c07b25e25ecfe584230c15eacecdc08fc1e2b658760fff8ab8ca464bae5eae8f792d65c35da9cee1c92e304ee296c4fa77175486d86fb2fb",
    ),
];

#[test]
fn aes_cbc_cts_matches_rfc_3962_with_both_adapters() {
    let key = bytes(RFC_3962_KEY);
    let message = bytes(RFC_3962_MESSAGE);
    let params = KeyWithIvRef::new(&key, &[0; 16]);
    let mut fixed = FixedCtsBlockCipher::<_, 16, Cbc>::cbc(AesEngine::new());
    for (length, expected) in AES_CBC {
        round_trip(&mut fixed, &params, &message[..length], &bytes(expected));
    }
    #[cfg(feature = "alloc")]
    {
        let mut allocating = CtsBlockCipher::cbc(AesEngine::new());
        for (length, expected) in AES_CBC {
            round_trip(
                &mut allocating,
                &params,
                &message[..length],
                &bytes(expected),
            );
        }
    }
}

#[test]
fn aes_ecb_cts_matches_bouncy_castle_with_both_adapters() {
    let key = bytes(RFC_3962_KEY);
    let message = bytes(RFC_3962_MESSAGE);
    let params = KeyRef::new(&key);
    let mut fixed = FixedCtsBlockCipher::<_, 16, Ecb>::ecb(AesEngine::new());
    for (length, expected) in AES_ECB {
        round_trip(&mut fixed, &params, &message[..length], &bytes(expected));
    }
    #[cfg(feature = "alloc")]
    {
        let mut allocating = CtsBlockCipher::ecb(AesEngine::new());
        for (length, expected) in AES_ECB {
            round_trip(
                &mut allocating,
                &params,
                &message[..length],
                &bytes(expected),
            );
        }
    }
}

/// CBC hands its params to the engine whole, so an engine with params of its own needs one type
/// that carries them and the IV.
struct Rc2WithIv<'a> {
    params: Rc2ParamsRef<'a>,
    iv: &'a [u8],
}

impl KeyParams for Rc2WithIv<'_> {
    fn key(&self) -> &[u8] {
        self.params.key()
    }
}

impl Rc2Params for Rc2WithIv<'_> {
    fn effective_key_bits(&self) -> usize {
        self.params.effective_key_bits()
    }
}

impl IvParams for Rc2WithIv<'_> {
    fn iv(&self) -> &[u8] {
        self.iv
    }
}

/// OpenSSL's `rc2-cbc -nopad` over the zero-padded message, with the last two blocks swapped and
/// cut to the message length.
const RC2_CBC: [(usize, &str); 7] = [
    (9, "464b6b8892320705b8"),
    (13, "4f3a692ac04d04efb8ecef2fe9"),
    (16, "cf7eed962b9136b4b8ecef2fe9fe6681"),
    (17, "b8ecef2fe9fe6681c61d7e4eb75ccbdbcf"),
    (
        31,
        "b8ecef2fe9fe6681cf7eed962b9136b4bea02525cde38f6e5f77a7b76c2fe6",
    ),
    (
        32,
        "b8ecef2fe9fe6681cf7eed962b9136b40c58afb8d2d5709a5f77a7b76c2fe698",
    ),
    (
        47,
        "b8ecef2fe9fe6681cf7eed962b9136b45f77a7b76c2fe6980c58afb8d2d5709ae1df95538fee21c16b8a09877104e9",
    ),
];

#[test]
fn rc2_cbc_cts_matches_openssl_with_both_adapters() {
    let key: Vec<u8> = (0..16).collect();
    let message = bytes(RFC_3962_MESSAGE);
    let params = Rc2WithIv {
        params: Rc2ParamsRef::new(&key),
        iv: &BC_IV,
    };
    let mut fixed = FixedCtsBlockCipher::<_, 8, Cbc>::cbc(Rc2Engine::new());
    for (length, expected) in RC2_CBC {
        round_trip(&mut fixed, &params, &message[..length], &bytes(expected));
    }
    #[cfg(feature = "alloc")]
    {
        let mut allocating = CtsBlockCipher::cbc(Rc2Engine::new());
        for (length, expected) in RC2_CBC {
            round_trip(
                &mut allocating,
                &params,
                &message[..length],
                &bytes(expected),
            );
        }
    }
}

#[test]
fn input_in_pieces_gives_the_same_output_and_update_sizes_are_exact() {
    let key = bytes(RFC_3962_KEY);
    let message = bytes(RFC_3962_MESSAGE);
    let params = KeyWithIvRef::new(&key, &[0; 16]);
    let mut cipher = FixedCtsBlockCipher::<_, 16, Cbc>::cbc(AesEngine::new());
    let whole = run(&mut cipher, CipherDirection::Encrypt, &params, &message);

    for piece in [1, 5, 16, 17, 33] {
        cipher.init(CipherDirection::Encrypt, &params).unwrap();
        let mut output = vec![0; message.len()];
        let mut written = 0;
        for chunk in message.chunks(piece) {
            let expected = cipher.update_output_len(chunk.len()).unwrap();
            let count = cipher.process_bytes(chunk, &mut output[written..]).unwrap();
            assert_eq!(count, expected, "pieces of {piece}");
            written += count;
        }
        written += cipher.do_final(&mut output[written..]).unwrap();
        assert_eq!(output[..written], whole[..], "pieces of {piece}");
    }
}

#[test]
#[should_panic(expected = "requires a positive block size equal to N")]
fn a_fixed_cipher_of_another_block_size_panics_as_it_is_made() {
    FixedCtsBlockCipher::<_, 8, Ecb>::ecb(AesEngine::new());
}

#[test]
fn errors_are_reported() {
    let key = [0x42; 16];
    let params = KeyWithIvRef::new(&key, &[0; 16]);
    let mut cipher = FixedCtsBlockCipher::<_, 16, Cbc>::cbc(AesEngine::new());
    assert_eq!(
        cipher.process_bytes(&[0; 16], &mut [0; 16]),
        Err(BufferedError::NotInitialized)
    );
    assert!(matches!(
        cipher.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &[0; 8])),
        Err(BlockModeInitError::InvalidIvLength(8))
    ));

    // Less than one whole block leaves nothing to steal from.
    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    cipher.process_bytes(&[0; 15], &mut []).unwrap();
    assert_eq!(
        cipher.do_final(&mut [0; 15]),
        Err(BufferedError::IncompleteLastBlock)
    );

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        cipher.process_bytes(&[0; 40], &mut [0; 15]),
        Err(BufferedError::OutputTooShort {
            required: 16,
            available: 15
        })
    );
    cipher.process_bytes(&[0; 20], &mut []).unwrap();
    assert_eq!(
        cipher.do_final(&mut [0; 19]),
        Err(BufferedError::OutputTooShort {
            required: 20,
            available: 19
        })
    );
}
