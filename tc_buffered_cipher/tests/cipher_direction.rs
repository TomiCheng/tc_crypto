use tc_buffered_cipher::CipherDirection;

#[test]
fn the_direction_converts_to_and_from_the_block_stream_and_asymmetric_cipher_contracts() {
    for (direction, block, stream, asym) in [
        (
            CipherDirection::Encrypt,
            tc_block_cipher::CipherDirection::Encrypt,
            tc_stream_cipher::CipherDirection::Encrypt,
            tc_asym_cipher::CipherDirection::Encrypt,
        ),
        (
            CipherDirection::Decrypt,
            tc_block_cipher::CipherDirection::Decrypt,
            tc_stream_cipher::CipherDirection::Decrypt,
            tc_asym_cipher::CipherDirection::Decrypt,
        ),
    ] {
        assert_eq!(CipherDirection::from(block), direction);
        assert_eq!(tc_block_cipher::CipherDirection::from(direction), block);
        assert_eq!(CipherDirection::from(stream), direction);
        assert_eq!(tc_stream_cipher::CipherDirection::from(direction), stream);
        assert_eq!(CipherDirection::from(asym), direction);
        assert_eq!(tc_asym_cipher::CipherDirection::from(direction), asym);
    }
}
