use tc_aes::AesEngine;
use tc_block_modes::{FixedCbcBlockCipher, KeyWithIvRef};
use tc_block_padding::{Pkcs7Padding, ZeroBytePadding};
use tc_buffered_cipher::{
    BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection, FixedBufferedBlockCipher,
    FixedPaddedBufferedBlockCipher,
};

type Cbc = FixedCbcBlockCipher<AesEngine, 16>;

const KEY: [u8; 16] = [0x42; 16];
const IV: [u8; 16] = [0x24; 16];

fn cbc() -> Cbc {
    FixedCbcBlockCipher::new(AesEngine::new())
}

/// Feeds `input` in two pieces split at `split` and returns everything written.
fn run<C: BufferedCipher>(cipher: &mut C, input: &[u8], split: usize) -> Result<Vec<u8>, C::Error> {
    let mut output = vec![0u8; cipher.output_len(input.len())?];
    let required = cipher.update_output_len(split)?;
    let mut written = cipher.process_bytes(&input[..split], &mut output[..required])?;
    written += cipher.process_bytes(&input[split..], &mut output[written..])?;
    written += cipher.do_final(&mut output[written..])?;
    output.truncate(written);
    Ok(output)
}

/// Encrypts `message` padded by hand with PKCS#7, through the unpadded adapter.
fn hand_padded(message: &[u8]) -> Vec<u8> {
    let pad = 16 - message.len() % 16;
    let mut padded = message.to_vec();
    padded.resize(message.len() + pad, pad as u8);
    let mut cipher = FixedBufferedBlockCipher::<_, 16>::new(cbc());
    cipher
        .init(CipherDirection::Encrypt, &KeyWithIvRef::new(&KEY, &IV))
        .unwrap();
    run(&mut cipher, &padded, 0).unwrap()
}

#[test]
fn pkcs7_over_cbc_matches_hand_padding_for_every_length_and_split() {
    let params = KeyWithIvRef::new(&KEY, &IV);
    let mut cipher = FixedPaddedBufferedBlockCipher::<_, 16>::new(cbc());

    for len in 0..=48 {
        let message: Vec<u8> = (0..len as u8).collect();
        let expected = hand_padded(&message);
        for split in 0..=len {
            cipher.init(CipherDirection::Encrypt, &params).unwrap();
            let sealed = run(&mut cipher, &message, split).unwrap();
            assert_eq!(sealed, expected, "length {len}, split {split}");

            cipher.init(CipherDirection::Decrypt, &params).unwrap();
            let opened = run(&mut cipher, &sealed, split.min(sealed.len())).unwrap();
            assert_eq!(opened, message, "length {len}, split {split}");
        }
    }
}

#[test]
fn a_full_final_block_is_followed_by_a_block_of_padding_alone_whatever_the_scheme() {
    let params = KeyWithIvRef::new(&KEY, &IV);
    let mut pkcs7 = FixedPaddedBufferedBlockCipher::<_, 16>::new(cbc());
    let mut zero =
        FixedPaddedBufferedBlockCipher::<_, 16, _>::with_padding(cbc(), ZeroBytePadding::new());

    for (len, sealed_len) in [(0, 16), (20, 32), (32, 48)] {
        let message = vec![0x07u8; len];
        pkcs7.init(CipherDirection::Encrypt, &params).unwrap();
        assert_eq!(run(&mut pkcs7, &message, 0).unwrap().len(), sealed_len);
        zero.init(CipherDirection::Encrypt, &params).unwrap();
        let sealed = run(&mut zero, &message, len / 2).unwrap();
        assert_eq!(sealed.len(), sealed_len, "length {len}");

        zero.init(CipherDirection::Decrypt, &params).unwrap();
        assert_eq!(run(&mut zero, &sealed, 0).unwrap(), message);
    }
}

#[test]
fn a_completed_final_block_is_held_back_until_do_final() {
    let params = KeyWithIvRef::new(&KEY, &IV);
    let mut cipher = FixedPaddedBufferedBlockCipher::<_, 16>::new(cbc());
    cipher.init(CipherDirection::Encrypt, &params).unwrap();

    assert_eq!(cipher.update_output_len(16), Ok(0));
    assert_eq!(cipher.process_bytes(&[0; 16], &mut [0; 16]), Ok(0));
    assert_eq!(cipher.update_output_len(1), Ok(16));
    assert_eq!(cipher.output_len(0), Ok(32));
    let mut output = [0u8; 32];
    assert_eq!(cipher.do_final(&mut output), Ok(32));
    assert_eq!(output.to_vec(), hand_padded(&[0; 16]));
}

#[test]
fn decryption_rejects_a_partial_block_and_corrupt_padding() {
    let params = KeyWithIvRef::new(&KEY, &IV);
    let mut cipher = FixedPaddedBufferedBlockCipher::<_, 16>::new(cbc());
    let mut sealed = hand_padded(&[0x55; 20]);

    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    assert!(matches!(
        run(&mut cipher, &sealed[..31], 5),
        Err(BufferedError::IncompleteLastBlock)
    ));

    // In CBC, flipping a byte of the first block flips the same byte of the
    // second plaintext block: here the PKCS#7 count, 0x0c, becomes 0x8c.
    sealed[15] ^= 0x80;
    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    assert!(matches!(
        run(&mut cipher, &sealed, 5),
        Err(BufferedError::CorruptPadding)
    ));
}

#[test]
fn ecb_built_from_a_bare_engine_pads_with_pkcs7_by_default() {
    let params = tc_block_cipher::KeyRef::new(&KEY);
    let mut padded = FixedPaddedBufferedBlockCipher::<_, 16>::from_cipher(AesEngine::new());
    let mut plain = FixedBufferedBlockCipher::<_, 16>::from_cipher(AesEngine::new());
    let message = [0x33u8; 21];
    let mut by_hand = message.to_vec();
    by_hand.resize(32, 11);

    padded.init(CipherDirection::Encrypt, &params).unwrap();
    plain.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(
        run(&mut padded, &message, 8).unwrap(),
        run(&mut plain, &by_hand, 8).unwrap()
    );
    assert_eq!(padded.padding(), &Pkcs7Padding::new());
    assert_eq!(padded.to_string(), "AES/ECB");
}

#[cfg(feature = "alloc")]
#[test]
fn the_allocating_padded_adapter_matches_the_fixed_one() {
    use tc_block_modes::CbcBlockCipher;
    use tc_buffered_cipher::PaddedBufferedBlockCipher;

    let params = KeyWithIvRef::new(&KEY, &IV);
    let mut cipher = PaddedBufferedBlockCipher::new(CbcBlockCipher::new(AesEngine::new()));
    for len in [0, 15, 16, 17, 47] {
        let message = vec![0x66u8; len];
        cipher.init(CipherDirection::Encrypt, &params).unwrap();
        let sealed = run(&mut cipher, &message, len / 3).unwrap();
        assert_eq!(sealed, hand_padded(&message), "length {len}");
        cipher.init(CipherDirection::Decrypt, &params).unwrap();
        assert_eq!(run(&mut cipher, &sealed, 7).unwrap(), message);
    }
}
