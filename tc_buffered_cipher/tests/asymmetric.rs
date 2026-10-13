#![cfg(feature = "alloc")]

use core::fmt::Debug;
use std::sync::OnceLock;

use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_asym_encoding::Pkcs1Encoding;
use tc_buffered_cipher::{
    BufferedAsymmetricBlockCipher, BufferedCipher, BufferedCipherInit, BufferedError,
    CipherDirection, FixedBufferedAsymmetricBlockCipher,
};
use tc_rsa::{RsaEngine, RsaKey, RsaKeyGenerationParamsOwned, RsaKeyGenerator};

/// The modulus length of the test key in bytes.
const K: usize = 128;
/// The longest message PKCS#1 v1.5 encrypts under the test key.
const PKCS1_LIMIT: usize = K - 11;

/// A 1024-bit key pair, generated once from a fixed seed: (public, private).
fn keys() -> &'static (RsaKey, RsaKey) {
    static KEYS: OnceLock<(RsaKey, RsaKey)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let mut generator = RsaKeyGenerator::new();
        let params = RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(1)).with_strength(1024);
        generator.init(params).unwrap();
        generator.generate_key_pair().unwrap()
    })
}

fn pkcs1() -> Pkcs1Encoding<RsaEngine, StdRng> {
    Pkcs1Encoding::from_parts(RsaEngine::new(), StdRng::seed_from_u64(2))
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|index| index as u8 ^ 0x5a).collect()
}

/// Feeds `input` in two pieces split at `split`, checks that nothing comes out
/// before `do_final` and returns what it writes.
fn run<C>(cipher: &mut C, input: &[u8], split: usize) -> Vec<u8>
where
    C: BufferedCipher,
    C::Error: Debug,
{
    let mut output = vec![0; cipher.output_len(input.len()).unwrap()];
    assert_eq!(cipher.update_output_len(input.len()).unwrap(), 0);
    assert_eq!(
        cipher.process_bytes(&input[..split], &mut output).unwrap(),
        0
    );
    assert_eq!(
        cipher.process_bytes(&input[split..], &mut output).unwrap(),
        0
    );
    let written = cipher.do_final(&mut output).unwrap();
    output.truncate(written);
    output
}

/// Encrypts `input` with the public key and decrypts it with the private one,
/// both split at `split`.
fn round_trip<C>(cipher: &mut C, input: &[u8], split: usize) -> Vec<u8>
where
    C: BufferedCipher + BufferedCipherInit<RsaKey>,
    <C as BufferedCipher>::Error: Debug,
    <C as BufferedCipherInit<RsaKey>>::Error: Debug,
{
    let (public, private) = keys();
    cipher.init(CipherDirection::Encrypt, public).unwrap();
    let sealed = run(cipher, input, split);
    assert_eq!(sealed.len(), K);
    cipher.init(CipherDirection::Decrypt, private).unwrap();
    run(cipher, &sealed, split.min(sealed.len()))
}

#[test]
fn a_pkcs1_message_round_trips_however_the_input_is_split() {
    let input = message(32);
    let mut fixed = FixedBufferedAsymmetricBlockCipher::<_, K>::new(pkcs1());
    let mut allocating = BufferedAsymmetricBlockCipher::new(pkcs1());
    for split in 0..=input.len() {
        assert_eq!(
            round_trip(&mut fixed, &input, split),
            input,
            "split {split}"
        );
        assert_eq!(
            round_trip(&mut allocating, &input, split),
            input,
            "split {split}"
        );
    }
}

#[test]
fn a_message_of_the_whole_input_block_round_trips() {
    let input = message(PKCS1_LIMIT);
    let mut fixed = FixedBufferedAsymmetricBlockCipher::<_, K>::new(pkcs1());
    let mut allocating = BufferedAsymmetricBlockCipher::new(pkcs1());
    assert_eq!(round_trip(&mut fixed, &input, 50), input);
    assert_eq!(round_trip(&mut allocating, &input, 50), input);
}

#[test]
fn input_is_taken_a_byte_at_a_time() {
    let (public, private) = keys();
    let input = message(20);
    let mut cipher = BufferedAsymmetricBlockCipher::new(pkcs1());

    cipher.init(CipherDirection::Encrypt, public).unwrap();
    let mut sealed = vec![0; cipher.output_len(0).unwrap()];
    for &byte in &input {
        assert_eq!(cipher.process_byte(byte, &mut []), Ok(0));
    }
    let written = cipher.do_final(&mut sealed).unwrap();

    cipher.init(CipherDirection::Decrypt, private).unwrap();
    assert_eq!(run(&mut cipher, &sealed[..written], 0), input);
}

#[test]
fn the_sizes_follow_the_cipher_in_each_direction() {
    let (public, private) = keys();
    let mut cipher = FixedBufferedAsymmetricBlockCipher::<_, K>::new(pkcs1());

    cipher.init(CipherDirection::Encrypt, public).unwrap();
    assert_eq!(cipher.block_size(), PKCS1_LIMIT);
    assert_eq!(cipher.update_output_len(1000), Ok(0));
    assert_eq!(cipher.output_len(0), Ok(K));

    cipher.init(CipherDirection::Decrypt, private).unwrap();
    assert_eq!(cipher.block_size(), K);
    assert_eq!(cipher.output_len(K), Ok(PKCS1_LIMIT));
}

#[test]
fn encrypting_takes_one_byte_more_than_the_input_block_for_padding_of_the_callers_own() {
    let (public, private) = keys();
    let mut cipher = BufferedAsymmetricBlockCipher::new(RsaEngine::new());

    // The raw engine takes K - 1 bytes; a whole block of K bytes below the
    // modulus fits too, as in Bouncy Castle.
    cipher.init(CipherDirection::Encrypt, public).unwrap();
    assert_eq!(cipher.block_size(), K - 1);
    let mut block = vec![0x01; K];
    block[1] = 0x23;
    let sealed = run(&mut cipher, &block, 7);
    cipher.init(CipherDirection::Encrypt, public).unwrap();
    assert_eq!(
        cipher.process_bytes(&[0x01; K + 1], &mut []),
        Err(BufferedError::InputTooLong)
    );

    // Decrypting takes no extra byte.
    cipher.init(CipherDirection::Decrypt, private).unwrap();
    assert_eq!(
        cipher.process_bytes(&[0x01; K + 1], &mut []),
        Err(BufferedError::InputTooLong)
    );
    assert_eq!(run(&mut cipher, &sealed, 0), block);
}

#[test]
fn a_message_that_outgrows_the_buffer_is_turned_down_and_the_buffer_kept() {
    let (public, private) = keys();
    let input = message(PKCS1_LIMIT + 2);
    let mut cipher = FixedBufferedAsymmetricBlockCipher::<_, K>::new(pkcs1());

    cipher.init(CipherDirection::Encrypt, public).unwrap();
    assert_eq!(cipher.process_bytes(&input[..100], &mut []), Ok(0));
    assert_eq!(
        cipher.process_bytes(&input[100..], &mut []),
        Err(BufferedError::InputTooLong)
    );
    let mut sealed = vec![0; K];
    let written = cipher.do_final(&mut sealed).unwrap();

    cipher.init(CipherDirection::Decrypt, private).unwrap();
    assert_eq!(run(&mut cipher, &sealed[..written], 0), input[..100]);
}

#[test]
fn the_extra_byte_encrypting_allows_reaches_an_encoding_that_turns_it_down() {
    let (public, _) = keys();
    let input = message(PKCS1_LIMIT + 1);
    let mut cipher = BufferedAsymmetricBlockCipher::new(pkcs1());

    cipher.init(CipherDirection::Encrypt, public).unwrap();
    assert_eq!(cipher.process_bytes(&input, &mut []), Ok(0));
    assert!(matches!(
        cipher.do_final(&mut [0; K]),
        Err(BufferedError::Cipher(_))
    ));
}

#[test]
fn a_fixed_buffer_too_short_for_the_key_fails_init_and_leaves_the_adapter_uninitialized() {
    let (public, private) = keys();
    let mut cipher = FixedBufferedAsymmetricBlockCipher::<_, 64>::new(pkcs1());

    assert_eq!(
        cipher.init(CipherDirection::Encrypt, public).err(),
        Some(BufferedError::BufferTooSmall {
            required: PKCS1_LIMIT + 1,
            available: 64,
        })
    );
    assert_eq!(
        cipher.process_bytes(b"a", &mut []),
        Err(BufferedError::NotInitialized)
    );
    assert_eq!(
        cipher.init(CipherDirection::Decrypt, private).err(),
        Some(BufferedError::BufferTooSmall {
            required: K,
            available: 64,
        })
    );
    assert_eq!(
        cipher.do_final(&mut [0; K]),
        Err(BufferedError::NotInitialized)
    );
}

#[test]
fn a_buffer_of_exactly_the_block_is_enough() {
    let (public, private) = keys();
    let mut cipher = FixedBufferedAsymmetricBlockCipher::<_, K>::new(RsaEngine::new());
    assert_eq!(cipher.init(CipherDirection::Encrypt, public), Ok(()));
    assert_eq!(cipher.init(CipherDirection::Decrypt, private), Ok(()));

    let mut cipher = FixedBufferedAsymmetricBlockCipher::<_, { K - 1 }>::new(RsaEngine::new());
    assert!(matches!(
        cipher.init(CipherDirection::Encrypt, public),
        Err(BufferedError::BufferTooSmall { required: K, .. })
    ));
}

#[test]
fn nothing_buffered_finishes_with_nothing_written() {
    let (public, _) = keys();
    let mut cipher = BufferedAsymmetricBlockCipher::new(pkcs1());
    cipher.init(CipherDirection::Encrypt, public).unwrap();
    assert_eq!(cipher.do_final(&mut []), Ok(0));
}

#[test]
fn an_adapter_not_yet_initialized_processes_nothing() {
    let mut fixed = FixedBufferedAsymmetricBlockCipher::<_, K>::new(pkcs1());
    let mut allocating = BufferedAsymmetricBlockCipher::new(pkcs1());
    assert_eq!(
        fixed.process_bytes(b"a", &mut []),
        Err(BufferedError::NotInitialized)
    );
    assert_eq!(
        fixed.do_final(&mut [0; K]),
        Err(BufferedError::NotInitialized)
    );
    assert_eq!(
        allocating.process_bytes(b"a", &mut []),
        Err(BufferedError::NotInitialized)
    );
    assert_eq!(
        allocating.do_final(&mut [0; K]),
        Err(BufferedError::NotInitialized)
    );
}

#[test]
fn an_output_shorter_than_the_output_block_is_turned_down_and_the_message_dropped() {
    let (public, _) = keys();
    let mut cipher = BufferedAsymmetricBlockCipher::new(pkcs1());
    cipher.init(CipherDirection::Encrypt, public).unwrap();
    cipher.process_bytes(b"attack at dawn", &mut []).unwrap();
    assert_eq!(
        cipher.do_final(&mut [0; K - 1]),
        Err(BufferedError::OutputTooShort {
            required: K,
            available: K - 1,
        })
    );
    assert_eq!(cipher.do_final(&mut [0; K]), Ok(0));
}

#[test]
fn reset_discards_the_buffered_input_and_keeps_the_key() {
    let (public, private) = keys();
    let mut cipher = BufferedAsymmetricBlockCipher::new(pkcs1());
    cipher.init(CipherDirection::Encrypt, public).unwrap();
    cipher.process_bytes(b"retreat", &mut []).unwrap();
    cipher.reset();
    let sealed = run(&mut cipher, b"attack at dawn", 6);

    cipher.init(CipherDirection::Decrypt, private).unwrap();
    assert_eq!(run(&mut cipher, &sealed, 0), b"attack at dawn");
}

#[test]
fn the_errors_of_the_cipher_come_through() {
    let (_, private) = keys();
    let mut cipher = BufferedAsymmetricBlockCipher::new(pkcs1());
    cipher.init(CipherDirection::Decrypt, private).unwrap();
    cipher.process_bytes(&[0x01; K], &mut []).unwrap();
    let error = cipher.do_final(&mut [0; K]).unwrap_err();
    assert!(matches!(error, BufferedError::Cipher(_)));
    assert!(core::error::Error::source(&error).is_some());
}

#[test]
fn the_adapter_is_named_after_its_cipher() {
    let fixed = FixedBufferedAsymmetricBlockCipher::<_, K>::new(pkcs1());
    let allocating = BufferedAsymmetricBlockCipher::new(pkcs1());
    assert_eq!(fixed.to_string(), pkcs1().to_string());
    assert_eq!(allocating.to_string(), "RSA/PKCS1Padding");
    assert_eq!(
        allocating.underlying_cipher().to_string(),
        "RSA/PKCS1Padding"
    );
}
