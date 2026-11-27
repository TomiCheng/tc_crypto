//! `BufferedIesCipher` over both IES engines, against Bouncy Castle's ECIESTest vectors: the
//! same static keys on secp192r1, KDF2 and HMAC over SHA-1, and Twofish/CBC for the cipher form.

#![cfg(feature = "ies")]

use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_block_modes::CbcBlockCipher;
use tc_buffered_cipher::{
    BufferedCipher, BufferedCipherInit, BufferedIesCipher, CipherDirection, IesCipherEngine,
    IesCipherParamsRef, IesEngine, IesError, IesInitParamsRef, IesParamsRef,
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
type Xor<'a> =
    BufferedIesCipher<IesEngine<EcdhBasicAgreement<Curve<'a>>, Kdf2<Sha1Digest>, Hmac<Sha1Digest>>>;
type WithCipher<'a> = BufferedIesCipher<
    IesCipherEngine<
        EcdhBasicAgreement<Curve<'a>>,
        Kdf2<Sha1Digest>,
        Hmac<Sha1Digest>,
        PaddedBufferedBlockCipher<CbcBlockCipher<TwofishEngine>>,
    >,
>;

const D: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const E: [u8; 8] = [8, 7, 6, 5, 4, 3, 2, 1];
const MESSAGE: &str = "1234567890abcdef";
const XOR_SEALED: &str = "609ae8fe2727572da30a1d04e3dd0530de24ee89e7313f6c400992a6";
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const CIPHER_SEALED: &str =
    "f246b0e26a2711992cac9c590d08e45c5e730b7c0f4218bb064e27b7dd7c8a3bd8bf01c3";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn xor<'a>() -> Xor<'a> {
    BufferedIesCipher::new(IesEngine::new(
        EcdhBasicAgreement::new(),
        Kdf2::new(Sha1Digest::new()),
        Hmac::new(Sha1Digest::new()),
    ))
}

fn with_cipher<'a>() -> WithCipher<'a> {
    BufferedIesCipher::new(IesCipherEngine::new(
        EcdhBasicAgreement::new(),
        Kdf2::new(Sha1Digest::new()),
        Hmac::new(Sha1Digest::new()),
        PaddedBufferedBlockCipher::new(CbcBlockCipher::new(TwofishEngine::new())),
    ))
}

/// Bouncy Castle's private key d and public key Q, handed to `check`.
fn with_keys(check: impl for<'c> FnOnce(&EcPrivateKey<Curve<'c>>, &EcPublicKey<Curve<'c>>)) {
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
    check(&private_key, &public_key);
}

/// Feeds `input` in pieces of `step` bytes and finishes.
fn run<C: BufferedCipher<Error = IesError>>(
    cipher: &mut C,
    input: &[u8],
    step: usize,
) -> Result<Vec<u8>, IesError> {
    let mut output = vec![0; cipher.output_len(input.len())?];
    let mut written = 0;
    for piece in input.chunks(step) {
        assert_eq!(cipher.update_output_len(piece.len())?, 0);
        written += cipher.process_bytes(piece, &mut output[written..])?;
    }
    written += cipher.do_final(&mut output[written..])?;
    output.truncate(written);
    Ok(output)
}

#[test]
fn the_xor_form_fed_in_pieces_matches_bcs_vector_and_decrypts_it() {
    with_keys(|private_key, public_key| {
        let params = IesParamsRef::new(&D, &E, 64);
        let init = IesInitParamsRef::new(private_key, public_key, &params);
        let mut sender = xor();
        sender.init(CipherDirection::Encrypt, &init).unwrap();
        let sealed = run(&mut sender, &hex(MESSAGE), 3).unwrap();
        assert_eq!(sealed, hex(XOR_SEALED));

        let mut receiver = xor();
        receiver.init(CipherDirection::Decrypt, &init).unwrap();
        assert_eq!(run(&mut receiver, &sealed, 5).unwrap(), hex(MESSAGE));
    });
}

#[test]
fn the_cipher_form_fed_in_pieces_matches_bcs_vector_and_decrypts_it() {
    with_keys(|private_key, public_key| {
        let iv = hex(IV);
        let params = IesCipherParamsRef::new(&D, &E, 64, 128).with_iv(&iv);
        let init = IesInitParamsRef::new(private_key, public_key, &params);
        let mut sender = with_cipher();
        sender.init(CipherDirection::Encrypt, &init).unwrap();
        let sealed = run(&mut sender, &hex(MESSAGE), 7).unwrap();
        assert_eq!(sealed, hex(CIPHER_SEALED));

        let mut receiver = with_cipher();
        receiver.init(CipherDirection::Decrypt, &init).unwrap();
        assert_eq!(run(&mut receiver, &sealed, 4).unwrap(), hex(MESSAGE));
    });
}

#[test]
fn the_keys_stay_for_the_next_message_after_do_final() {
    with_keys(|private_key, public_key| {
        let params = IesParamsRef::new(&D, &E, 64);
        let mut sender = xor();
        sender
            .init(
                CipherDirection::Encrypt,
                &IesInitParamsRef::new(private_key, public_key, &params),
            )
            .unwrap();
        let first = run(&mut sender, &hex(MESSAGE), 16).unwrap();
        assert_eq!(run(&mut sender, &hex(MESSAGE), 16).unwrap(), first);
    });
}

#[test]
fn reset_discards_the_buffered_input() {
    with_keys(|private_key, public_key| {
        let params = IesParamsRef::new(&D, &E, 64);
        let mut sender = xor();
        sender
            .init(
                CipherDirection::Encrypt,
                &IesInitParamsRef::new(private_key, public_key, &params),
            )
            .unwrap();
        sender.process_bytes(b"left over", &mut []).unwrap();
        sender.reset();
        assert_eq!(
            run(&mut sender, &hex(MESSAGE), 16).unwrap(),
            hex(XOR_SEALED)
        );
    });
}

#[test]
fn a_short_output_is_refused_and_keeps_the_message() {
    with_keys(|private_key, public_key| {
        let params = IesParamsRef::new(&D, &E, 64);
        let mut sender = xor();
        sender
            .init(
                CipherDirection::Encrypt,
                &IesInitParamsRef::new(private_key, public_key, &params),
            )
            .unwrap();
        sender.process_bytes(&hex(MESSAGE), &mut []).unwrap();
        let mut short = [0; 4];
        assert!(matches!(
            sender.do_final(&mut short),
            Err(IesError::OutputTooShort)
        ));
        let mut output = vec![0; sender.output_len(0).unwrap()];
        let written = sender.do_final(&mut output).unwrap();
        assert_eq!(&output[..written], hex(XOR_SEALED));
    });
}

#[test]
fn a_tampered_message_fails_the_mac_and_writes_nothing() {
    with_keys(|private_key, public_key| {
        let params = IesParamsRef::new(&D, &E, 64);
        let mut receiver = xor();
        receiver
            .init(
                CipherDirection::Decrypt,
                &IesInitParamsRef::new(private_key, public_key, &params),
            )
            .unwrap();
        let mut sealed = hex(XOR_SEALED);
        sealed[0] ^= 1;
        receiver.process_bytes(&sealed, &mut []).unwrap();
        let mut output = vec![0xAA; receiver.output_len(0).unwrap()];
        assert!(matches!(
            receiver.do_final(&mut output),
            Err(IesError::InvalidMac)
        ));
        assert!(output.iter().all(|&byte| byte == 0xAA));
    });
}

#[test]
fn every_call_before_init_is_refused() {
    let mut cipher = xor();
    assert!(matches!(
        cipher.process_bytes(b"x", &mut []),
        Err(IesError::NotInitialised)
    ));
    assert!(matches!(
        cipher.output_len(0),
        Err(IesError::NotInitialised)
    ));
    assert!(matches!(
        cipher.update_output_len(0),
        Err(IesError::NotInitialised)
    ));
    assert_eq!(cipher.block_size(), 0);
}
