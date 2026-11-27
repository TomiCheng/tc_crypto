//! Bouncy Castle's ECIESTest, XOR form: both parties use the same static keys on secp192r1,
//! with KDF2 and HMAC over SHA-1.

#![cfg(feature = "ies")]

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_buffered_cipher::{CipherDirection, IesEngine, IesError, IesParamsOwned, IesParamsRef};
use tc_ec_agreement::EcdhBasicAgreement;
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_fp_custom::named_curves::SECP192R1;
use tc_fp_custom::{SecP192R1FieldElement, SecPCtCurve};
use tc_kdf::kdf::Kdf2;
use tc_macs::Hmac;
use tc_sha::Sha1Digest;

type Curve<'a> = &'a SecPCtCurve<SecP192R1FieldElement>;
type Engine<'a> = IesEngine<EcdhBasicAgreement<Curve<'a>>, Kdf2<Sha1Digest>, Hmac<Sha1Digest>>;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn engine<'a>() -> Engine<'a> {
    IesEngine::new(
        EcdhBasicAgreement::new(),
        Kdf2::new(Sha1Digest::new()),
        Hmac::new(Sha1Digest::new()),
    )
}

const D: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const E: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
const MESSAGE: &str = "1234567890abcdef";
const SEALED: &str = "609ae8fe2727572da30a1d04e3dd0530de24ee89e7313f6c400992a6";

/// The sender and receiver over the private key d and the public key Q of Bouncy Castle's
/// test, handed to `check`.
fn with_engines(check: impl FnOnce(Engine<'_>, Engine<'_>)) {
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
    let params = IesParamsRef::new(&D, &E, 64);

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
fn the_xor_form_matches_bcs_ecies_vector_and_decrypts_it() {
    with_engines(|mut sender, mut receiver| {
        let sealed = sender.process_block(&hex(MESSAGE)).unwrap();
        assert_eq!(sealed, hex(SEALED));
        assert_eq!(receiver.process_block(&sealed).unwrap(), hex(MESSAGE));
    });
}

#[test]
fn every_message_under_the_same_keys_is_sealed_the_same_way() {
    with_engines(|mut sender, _| {
        let first = sender.process_block(&hex(MESSAGE)).unwrap();
        assert_eq!(sender.process_block(&hex(MESSAGE)).unwrap(), first);
    });
}

#[test]
fn a_changed_byte_anywhere_fails_the_mac() {
    with_engines(|_, mut receiver| {
        let sealed = hex(SEALED);
        for index in [0, 7, 8, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[index] ^= 1;
            assert!(
                matches!(receiver.process_block(&tampered), Err(IesError::InvalidMac)),
                "{index}"
            );
        }
    });
}

#[test]
fn input_shorter_than_the_mac_is_refused() {
    with_engines(|_, mut receiver| {
        assert!(matches!(
            receiver.process_block(&[0; 19]),
            Err(IesError::InputTooShort)
        ));
        // A MAC and no ciphertext: the MAC of an empty message does not match
        assert!(matches!(
            receiver.process_block(&[0; 20]),
            Err(IesError::InvalidMac)
        ));
    });
}

#[test]
fn a_mac_key_length_that_is_not_whole_bytes_is_refused() {
    let curve = SECP192R1.ct_curve();
    let g = SECP192R1.ct_generator(&curve);
    let private_key = EcPrivateKey::<Curve<'_>>::new(g.clone(), PaddedBigUint::from(7u8)).unwrap();
    let public_key = EcPublicKey::<Curve<'_>>::new(g.clone(), &g).unwrap();
    let mut sender = engine();
    assert!(matches!(
        sender.init(
            CipherDirection::Encrypt,
            &private_key,
            &public_key,
            &IesParamsRef::new(&D, &E, 65)
        ),
        Err(IesError::InvalidKeyLength(65))
    ));
    assert!(matches!(
        sender.process_block(b"message"),
        Err(IesError::NotInitialised)
    ));
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
    let params = IesParamsOwned::new(D.to_vec(), E.to_vec(), 64);

    let mut sender = engine();
    sender
        .init(CipherDirection::Encrypt, &private_key, &public_key, &params)
        .unwrap();
    assert_eq!(sender.process_block(&hex(MESSAGE)).unwrap(), hex(SEALED));
}
