use tc_buffered_cipher::{
    BufferedCipher, BufferedCipherInit, BufferedError, BufferedStreamCipher, CipherDirection,
};
use tc_chacha::ChaCha7539Engine;
use tc_stream_cipher::{KeyWithIvRef, StreamCipher, StreamCipherInit};

fn decode(hex: &str) -> Vec<u8> {
    let hex: Vec<u8> = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    hex.chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

// RFC 8439, appendix A.2, test vector #1: an all-zero key, nonce and
// plaintext from block counter 0, so the ciphertext is the keystream itself.
const KEYSTREAM: &str = "76b8e0ada0f13d90405d6ae55386bd28 bdd219b8a08ded1aa836efcc8b770dc7
                         da41597c5157488d7724e03fb8d84a37 6a43b8f41518a11cc387b669b2ee6586";

/// Feeds `input` in two pieces split at `split` and returns everything written.
fn run<C>(cipher: &mut C, input: &[u8], split: usize) -> Vec<u8>
where
    C: BufferedCipher,
    C::Error: core::fmt::Debug,
{
    let mut output = vec![0u8; cipher.output_len(input.len()).unwrap()];
    let mut written = cipher.process_bytes(&input[..split], &mut output).unwrap();
    written += cipher
        .process_bytes(&input[split..], &mut output[written..])
        .unwrap();
    written += cipher.do_final(&mut output[written..]).unwrap();
    output.truncate(written);
    output
}

#[test]
fn chacha20_matches_the_rfc_8439_vector_however_the_input_is_split() {
    let (key, nonce) = ([0u8; 32], [0u8; 12]);
    let params = KeyWithIvRef::new(&key, &nonce);
    let plaintext = [0u8; 64];
    let keystream = decode(KEYSTREAM);
    let mut cipher = BufferedStreamCipher::new(ChaCha7539Engine::new());

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    for split in 0..=plaintext.len() {
        // do_final restarts the keystream, so every round sees the same one.
        assert_eq!(
            run(&mut cipher, &plaintext, split),
            keystream,
            "split {split}"
        );
    }

    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    let mut recovered = [0xffu8; 64];
    for (index, &byte) in keystream.iter().enumerate() {
        assert_eq!(cipher.process_byte(byte, &mut recovered[index..]), Ok(1));
    }
    assert_eq!(recovered, plaintext);
}

#[test]
fn the_adapter_writes_what_the_engine_writes_over_several_blocks() {
    let (key, nonce) = ([0x42u8; 32], [0x24u8; 12]);
    let params = KeyWithIvRef::new(&key, &nonce);
    let message: Vec<u8> = (0..150u8).collect();

    let mut engine = ChaCha7539Engine::new();
    engine
        .init(tc_stream_cipher::CipherDirection::Encrypt, &params)
        .unwrap();
    let mut expected = vec![0u8; message.len()];
    engine.process_bytes(&message, &mut expected).unwrap();

    let mut cipher = BufferedStreamCipher::new(ChaCha7539Engine::new());
    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    for split in [0, 1, 63, 64, 65, 128, 149, 150] {
        assert_eq!(run(&mut cipher, &message, split), expected, "split {split}");
    }

    cipher.init(CipherDirection::Decrypt, &params).unwrap();
    assert_eq!(run(&mut cipher, &expected, 77), message);
}

#[test]
fn sizes_match_the_input_and_misuse_is_reported() {
    let (key, nonce) = ([0x42u8; 32], [0x24u8; 12]);
    let params = KeyWithIvRef::new(&key, &nonce);
    let mut cipher = BufferedStreamCipher::new(ChaCha7539Engine::new());

    assert!(matches!(
        cipher.process_bytes(&[0; 4], &mut [0; 4]),
        Err(BufferedError::NotInitialized)
    ));
    assert!(matches!(
        cipher.process_byte(0, &mut [0]),
        Err(BufferedError::NotInitialized)
    ));
    assert!(matches!(
        cipher.do_final(&mut []),
        Err(BufferedError::NotInitialized)
    ));

    cipher.init(CipherDirection::Encrypt, &params).unwrap();
    assert_eq!(cipher.block_size(), 0);
    assert_eq!(cipher.update_output_len(7), Ok(7));
    assert_eq!(cipher.output_len(7), Ok(7));
    assert!(matches!(
        cipher.process_bytes(&[0; 4], &mut [0; 3]),
        Err(BufferedError::OutputTooShort {
            required: 4,
            available: 3
        })
    ));
    assert!(matches!(
        cipher.process_byte(0, &mut []),
        Err(BufferedError::OutputTooShort {
            required: 1,
            available: 0
        })
    ));
    assert_eq!(cipher.to_string(), "ChaCha7539");
}
