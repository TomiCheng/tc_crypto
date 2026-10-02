use tc_aes::AesEngine;
use tc_block_cipher::KeyRef;
use tc_block_modes::{FixedCbcBlockCipher, FixedCtrBlockCipher, KeyWithIvRef};
use tc_buffered_cipher::{
    BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection, FixedBufferedBlockCipher,
};

fn decode(hex: &str) -> Vec<u8> {
    let hex: Vec<u8> = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    hex.chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// NIST SP 800-38A, F.2.1 and F.5.1: AES-128 with the same key and plaintext.
const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
                         30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710";
const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const CBC_CIPHERTEXT: &str = "7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2
                              73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7";
const CTR_IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const CTR_CIPHERTEXT: &str = "874d6191b620e3261bef6864990db6ce 9806f66b7970fdff8617187bb9fffdff
                              5ae4df3edbd5d35e5b4f09020db03eab 1e031dda2fbe03d1792170a0f3009cee";

/// Feeds `input` in two pieces split at `split` and returns everything written.
fn run<C>(cipher: &mut C, input: &[u8], split: usize) -> Vec<u8>
where
    C: BufferedCipher,
    C::Error: core::fmt::Debug,
{
    let mut output = vec![0u8; cipher.output_len(input.len()).unwrap()];
    let mut written = 0;
    for piece in [&input[..split], &input[split..]] {
        let required = cipher.update_output_len(piece.len()).unwrap();
        written += cipher
            .process_bytes(piece, &mut output[written..written + required])
            .unwrap();
    }
    written += cipher.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

#[test]
fn cbc_over_aes_matches_the_sp_800_38a_vector_however_the_input_is_split() {
    let (key, iv) = (decode(KEY), decode(CBC_IV));
    let (plaintext, ciphertext) = (decode(PLAINTEXT), decode(CBC_CIPHERTEXT));
    let params = KeyWithIvRef::new(&key, &iv);
    let mut cipher =
        FixedBufferedBlockCipher::<_, 16>::new(FixedCbcBlockCipher::<_, 16>::new(AesEngine::new()));

    for split in 0..=plaintext.len() {
        cipher.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(
            run(&mut cipher, &plaintext, split),
            ciphertext,
            "split {split}"
        );
        cipher.init(CipherDirection::Decrypt, &params).unwrap();
        assert_eq!(
            run(&mut cipher, &ciphertext, split),
            plaintext,
            "split {split}"
        );
    }
}

#[test]
fn ctr_over_aes_matches_the_sp_800_38a_vector_and_finishes_a_partial_block() {
    let (key, iv) = (decode(KEY), decode(CTR_IV));
    let (plaintext, ciphertext) = (decode(PLAINTEXT), decode(CTR_CIPHERTEXT));
    let params = KeyWithIvRef::new(&key, &iv);
    let mut cipher =
        FixedBufferedBlockCipher::<_, 16>::new(FixedCtrBlockCipher::<_, 16>::new(AesEngine::new()));

    // A keystream mode encrypts a truncated message to the same prefix.
    for len in [plaintext.len(), 37, 15, 1] {
        for split in 0..=len {
            cipher.init(CipherDirection::Encrypt, &params).unwrap();
            assert_eq!(
                run(&mut cipher, &plaintext[..len], split),
                ciphertext[..len]
            );
            cipher.init(CipherDirection::Decrypt, &params).unwrap();
            assert_eq!(
                run(&mut cipher, &ciphertext[..len], split),
                plaintext[..len]
            );
        }
    }
}

#[test]
fn ecb_built_from_a_bare_aes_engine_matches_the_fips_197_vector() {
    let key = decode("000102030405060708090a0b0c0d0e0f");
    let plaintext = decode("00112233445566778899aabbccddeeff");
    let ciphertext = decode("69c4e0d86a7b0430d8cdb78070b4c55a");
    let params = KeyRef::new(&key);
    let mut cipher = FixedBufferedBlockCipher::<_, 16>::from_cipher(AesEngine::new());

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(run(&mut cipher, &plaintext, 5), ciphertext);
    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(run(&mut cipher, &ciphertext, 11), plaintext);
    assert_eq!(cipher.block_size(), 16);
    assert_eq!(cipher.to_string(), "AES/ECB");
}

#[test]
fn a_partial_final_cbc_block_is_rejected_and_the_next_message_starts_over() {
    let (key, iv) = (decode(KEY), decode(CBC_IV));
    let (plaintext, ciphertext) = (decode(PLAINTEXT), decode(CBC_CIPHERTEXT));
    let params = KeyWithIvRef::new(&key, &iv);
    let mut cipher =
        FixedBufferedBlockCipher::<_, 16>::new(FixedCbcBlockCipher::<_, 16>::new(AesEngine::new()));
    cipher.init(CipherDirection::Encrypt, &params).unwrap();

    let mut output = [0u8; 64];
    assert_eq!(cipher.process_bytes(&plaintext[..20], &mut output), Ok(16));
    assert_eq!(output[..16], ciphertext[..16]);
    assert!(matches!(
        cipher.do_final(&mut output),
        Err(BufferedError::IncompleteLastBlock)
    ));

    // do_final returned the mode to its IV, so the same message encrypts the same way.
    assert_eq!(run(&mut cipher, &plaintext, 7), ciphertext);
}

#[test]
fn processing_before_init_short_outputs_and_overflowing_sizes_are_reported() {
    let (key, iv) = (decode(KEY), decode(CBC_IV));
    let params = KeyWithIvRef::new(&key, &iv);
    let mut cipher =
        FixedBufferedBlockCipher::<_, 16>::new(FixedCbcBlockCipher::<_, 16>::new(AesEngine::new()));

    assert!(matches!(
        cipher.process_bytes(&[0; 16], &mut [0; 16]),
        Err(BufferedError::NotInitialized)
    ));
    assert!(matches!(
        cipher.do_final(&mut []),
        Err(BufferedError::NotInitialized)
    ));

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert!(matches!(
        cipher.process_bytes(&[0; 17], &mut [0; 15]),
        Err(BufferedError::OutputTooShort {
            required: 16,
            available: 15
        })
    ));
    cipher.process_bytes(&[0; 3], &mut []).unwrap();
    assert_eq!(cipher.update_output_len(13), Ok(16));
    assert!(matches!(
        cipher.output_len(usize::MAX),
        Err(BufferedError::InputTooLong)
    ));
    assert!(matches!(
        cipher.update_output_len(usize::MAX),
        Err(BufferedError::InputTooLong)
    ));
}

#[cfg(feature = "alloc")]
#[test]
fn the_allocating_adapter_matches_the_fixed_one_over_cbc_and_ctr() {
    use tc_block_modes::{CbcBlockCipher, CtrBlockCipher};
    use tc_buffered_cipher::BufferedBlockCipher;

    let key = decode(KEY);
    let plaintext = decode(PLAINTEXT);

    let (cbc_iv, cbc_ciphertext) = (decode(CBC_IV), decode(CBC_CIPHERTEXT));
    let params = KeyWithIvRef::new(&key, &cbc_iv);
    let mut cbc = BufferedBlockCipher::new(CbcBlockCipher::new(AesEngine::new()));
    cbc.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(run(&mut cbc, &plaintext, 23), cbc_ciphertext);

    let (ctr_iv, ctr_ciphertext) = (decode(CTR_IV), decode(CTR_CIPHERTEXT));
    let params = KeyWithIvRef::new(&key, &ctr_iv);
    let mut ctr = BufferedBlockCipher::new(CtrBlockCipher::new(AesEngine::new()));
    ctr.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(run(&mut ctr, &ctr_ciphertext[..41], 9), plaintext[..41]);
    assert_eq!(ctr.block_size(), 16);
}
