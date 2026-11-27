//! Bouncy Castle's ECIESTest, cipher form: the same static keys, Twofish/CBC with PKCS#7,
//! K1 of 128 bits and K2 of 64.

#![cfg(feature = "ies")]

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_block_modes::CbcBlockCipher;
use tc_buffered_cipher::{
    CipherDirection, IesCipherEngine, IesCipherParamsOwned, IesCipherParamsRef, IesError,
    PaddedBufferedBlockCipher,
};
use tc_ec_agreement::EcdhBasicAgreement;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_fp_custom::named_curves::SECP192R1;
use tc_fp_custom::{SecP192R1FieldElement, SecPCtCurve};
use tc_kdf::kdf::Kdf2;
use tc_macs::Hmac;
use tc_sha::Sha1Digest;
use tc_twofish::TwofishEngine;

type Curve<'a> = &'a SecPCtCurve<SecP192R1FieldElement>;
type Engine<'a> = IesCipherEngine<
    EcdhBasicAgreement<Curve<'a>>,
    Kdf2<Sha1Digest>,
    Hmac<Sha1Digest>,
    PaddedBufferedBlockCipher<CbcBlockCipher<TwofishEngine>>,
>;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn engine<'a>() -> Engine<'a> {
    IesCipherEngine::new(
        EcdhBasicAgreement::new(),
        Kdf2::new(Sha1Digest::new()),
        Hmac::new(Sha1Digest::new()),
        PaddedBufferedBlockCipher::new(CbcBlockCipher::new(TwofishEngine::new())),
    )
}

const D: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const E: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
const MESSAGE: &str = "1234567890abcdef";

/// The sender and receiver over the private key d and the public key Q of Bouncy Castle's
/// test, with the IV given, handed to `check`.
fn with_engines(iv: &[u8], check: impl FnOnce(Engine<'_>, Engine<'_>)) {
    let curve = SECP192R1.ct_curve();
    let g = SECP192R1.ct_generator(&curve);
    let d = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(
        "1a8d598fc15bf0fd89030b5cb1111aeb92ae8baf5ea475fb",
    ))
    .unwrap();
    let q = curve
        .decode_point(&hex("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5"))
        .unwrap();
    let private_key = EcPrivateKey::<Curve<'_>>::new(g.clone(), d).unwrap();
    let public_key = EcPublicKey::<Curve<'_>>::new(g, &q).unwrap();
    let params = IesCipherParamsRef::new(&D, &E, 64, 128).with_iv(iv);

    let mut sender = engine();
    sender
        .init(CipherDirection::Encrypt, &private_key, &public_key, &params)
        .unwrap();
    let mut receiver = engine();
    receiver
        .init(CipherDirection::Decrypt, &private_key, &public_key, &params)
        .unwrap();
    check(sender, receiver);
}

#[test]
fn twofish_cbc_with_bcs_iv_matches_its_vector_and_decrypts_it() {
    with_engines(
        &hex("000102030405060708090a0b0c0d0e0f"),
        |mut sender, mut receiver| {
            let sealed = sender.process_block(&hex(MESSAGE)).unwrap();
            assert_eq!(
                sealed,
                hex("f246b0e26a2711992cac9c590d08e45c5e730b7c0f4218bb064e27b7dd7c8a3bd8bf01c3")
            );
            assert_eq!(receiver.process_block(&sealed).unwrap(), hex(MESSAGE));
        },
    );
}

#[test]
fn a_zero_iv_gives_bcs_vector_without_an_iv() {
    // Bouncy Castle's CBC uses zeros when no IV is given; tc_block_modes' CBC needs one, so
    // pass zeros
    with_engines(&[0; 16], |mut sender, mut receiver| {
        let sealed = sender.process_block(&hex(MESSAGE)).unwrap();
        assert_eq!(
            sealed,
            hex("b8a06ea5c2b9df28b58a0a90a734cde8c9c02903e5c220021fe4417410d1e53a32a71696")
        );
        assert_eq!(receiver.process_block(&sealed).unwrap(), hex(MESSAGE));
    });
}

#[test]
fn cbc_refuses_to_run_without_an_iv() {
    with_engines(&[], |mut sender, _| {
        assert!(matches!(
            sender.process_block(&hex(MESSAGE)),
            Err(IesError::Cipher(_))
        ));
    });
}

#[test]
fn a_tampered_last_block_fails_the_mac_before_the_padding_is_checked() {
    with_engines(&[0; 16], |mut sender, mut receiver| {
        let mut sealed = sender.process_block(&hex(MESSAGE)).unwrap();
        // Change the last block of the ciphertext: without the MAC this would be a padding
        // error
        sealed[15] ^= 0xff;
        assert!(matches!(
            receiver.process_block(&sealed),
            Err(IesError::InvalidMac)
        ));
    });
}

#[test]
fn owned_params_seal_as_borrowed_ones_do() {
    let curve = SECP192R1.ct_curve();
    let g = SECP192R1.ct_generator(&curve);
    let d = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&hex(
        "1a8d598fc15bf0fd89030b5cb1111aeb92ae8baf5ea475fb",
    ))
    .unwrap();
    let q = curve
        .decode_point(&hex("0262b12d60690cdcf330babab6e69763b471f994dd702d16a5"))
        .unwrap();
    let private_key = EcPrivateKey::<Curve<'_>>::new(g.clone(), d).unwrap();
    let public_key = EcPublicKey::<Curve<'_>>::new(g, &q).unwrap();
    let params = IesCipherParamsOwned::new(D.to_vec(), E.to_vec(), 64, 128)
        .with_iv(hex("000102030405060708090a0b0c0d0e0f"));

    let mut sender = engine();
    sender
        .init(CipherDirection::Encrypt, &private_key, &public_key, &params)
        .unwrap();
    assert_eq!(
        sender.process_block(&hex(MESSAGE)).unwrap(),
        hex("f246b0e26a2711992cac9c590d08e45c5e730b7c0f4218bb064e27b7dd7c8a3bd8bf01c3")
    );
}
