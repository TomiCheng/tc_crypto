use tc_aead_cipher::{AeadError, AeadInitError, AeadParamsRef, GcmBlockCipher};
use tc_aes::AesEngine;
use tc_buffered_cipher::{
    BufferedAeadBlockCipher, BufferedCipher, BufferedCipherInit, CipherDirection,
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

// The GCM specification by McGrew and Viega, test case 4: AES-128 with a
// 96-bit IV, 20 bytes of associated data and a 60-byte plaintext.
const KEY: &str = "feffe9928665731c6d6a8f9467308308";
const IV: &str = "cafebabefacedbaddecaf888";
const AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const PLAINTEXT: &str = "d9313225f88406e5a55909c5aff5269a 86a7a9531534f7da2e4c303d8a318a72
                         1c3c0c95956809532fcf0e2449a6b525 b16aedf5aa0de657ba637b39";
const CIPHERTEXT_AND_TAG: &str = "42831ec2217774244b7221b784d0d49c e3aa212f2c02a4e035c17e2329aca12e
                                  21d514b25466931c7d8f6a5aac84aa05 1ba30b396a0aac973d58e091
                                  5bc94fbc3221a5db94fae95ae7121a47";

fn gcm() -> BufferedAeadBlockCipher<GcmBlockCipher<AesEngine>> {
    BufferedAeadBlockCipher::new(GcmBlockCipher::new(AesEngine::new()))
}

/// Feeds `input` in two pieces split at `split` and returns everything written.
fn run<C>(cipher: &mut C, input: &[u8], split: usize) -> Result<Vec<u8>, C::Error>
where
    C: BufferedCipher,
{
    let mut output = vec![0u8; cipher.output_len(input.len())?];
    let required = cipher.update_output_len(split)?;
    let mut written = cipher.process_bytes(&input[..split], &mut output[..required])?;
    written += cipher.process_bytes(&input[split..], &mut output[written..])?;
    written += cipher.do_final(&mut output[written..])?;
    output.truncate(written);
    Ok(output)
}

#[test]
fn gcm_over_aes_matches_test_case_4_however_the_input_is_split() {
    let (key, iv, aad) = (decode(KEY), decode(IV), decode(AAD));
    let (plaintext, sealed) = (decode(PLAINTEXT), decode(CIPHERTEXT_AND_TAG));
    // The buffered interface has no method for associated data; it goes in
    // as the initial associated data of the parameters.
    let params = AeadParamsRef::new(&key, &iv, 16, &aad);

    let mut decryptor = gcm();
    for split in 0..=plaintext.len() {
        // Encryption refuses a repeated key and nonce, so each round takes a fresh engine.
        let mut encryptor = gcm();
        encryptor.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(
            run(&mut encryptor, &plaintext, split).unwrap(),
            sealed,
            "split {split}"
        );

        decryptor.init(CipherDirection::Decrypt, &params).unwrap();
        assert_eq!(
            run(&mut decryptor, &sealed, split).unwrap(),
            plaintext,
            "split {split}"
        );
    }
}

#[test]
fn a_modified_tag_fails_with_the_engines_own_error() {
    let (key, iv, aad) = (decode(KEY), decode(IV), decode(AAD));
    let mut sealed = decode(CIPHERTEXT_AND_TAG);
    *sealed.last_mut().unwrap() ^= 1;
    let params = AeadParamsRef::new(&key, &iv, 16, &aad);

    let mut cipher = gcm();
    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(
        run(&mut cipher, &sealed, 30),
        Err(AeadError::AuthenticationFailed)
    );
}

#[test]
fn the_block_size_name_and_engine_errors_pass_through() {
    let (key, iv) = (decode(KEY), decode(IV));
    let params = AeadParamsRef::new(&key, &iv, 16, &[]);
    let mut cipher = gcm();

    assert_eq!(
        cipher.process_bytes(&[0; 16], &mut [0; 16]),
        Err(AeadError::NotInitialized)
    );

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.block_size(), 16);
    assert_eq!(cipher.to_string(), "AES/GCM");
    assert_eq!(cipher.output_len(60), Ok(76));
    assert_eq!(
        cipher.init(CipherDirection::Encrypt, &params),
        Err(AeadInitError::NonceReuse)
    );
}
