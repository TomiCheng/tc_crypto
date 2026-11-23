//! Known-answer tests from NIST CAVP's `drbgtestvectors.zip`.
//!
//! The source files are `HMAC_DRBG.rsp`, `Hash_DRBG.rsp` and `CTR_DRBG.rsp` in
//! each of `drbgvectors_no_reseed`, `drbgvectors_pr_false` and
//! `drbgvectors_pr_true`.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_aes::AesEngine;
use tc_drbg::{CtrDrbg, Drbg, HashDrbg, HmacDrbg};
use tc_macs::Hmac;
use tc_sha::{Sha256Digest, Sha512Digest};

struct FixedRng {
    bytes: Vec<u8>,
    offset: usize,
}

impl FixedRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.offset + output.len();
        output.copy_from_slice(
            self.bytes
                .get(self.offset..end)
                .expect("the test RNG holds enough CAVP entropy"),
        );
        self.offset = end;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len() % 2 == 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn generate_twice<D: Drbg>(
    drbg: &mut D,
    first_input: &[u8],
    second_input: &[u8],
    length: usize,
) -> Vec<u8> {
    let mut output = vec![0_u8; length];
    drbg.generate(&mut output, first_input).unwrap();
    drbg.generate(&mut output, second_input).unwrap();
    output
}

#[test]
fn hmac_sha256_without_additional_input_matches_cavp() {
    // drbgvectors_no_reseed/HMAC_DRBG.rsp, SHA-256, COUNT = 0.
    let entropy = hex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488");
    let nonce = hex("659ba96c601dc69fc902940805ec0ca8");
    let expected = hex(
        "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b8\
         9d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc\
         107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde066\
         8961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = HmacDrbg::new(
        Hmac::new(Sha256Digest::new()),
        256,
        32,
        &mut rng,
        &nonce,
        &[],
    )
    .unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &[], &[], expected.len()),
        expected
    );
}

#[test]
fn hmac_sha256_with_additional_input_matches_cavp() {
    // drbgvectors_no_reseed/HMAC_DRBG.rsp, SHA-256, COUNT = 0, with additional input.
    let entropy = hex("d3cc4d1acf3dde0c4bd2290d262337042dc632948223d3a2eaab87da44295fbd");
    let nonce = hex("0109b0e729f457328aa18569a9224921");
    let first = hex("3c311848183c9a212a26f27f8c6647e40375e466a0857cc39c4e47575d53f1f6");
    let second = hex("fcb9abd19ccfbccef88c9c39bfb3dd7b1c12266c9808992e305bc3cff566e4e4");
    let expected = hex(
        "9c7b758b212cd0fcecd5daa489821712e3cdea4467b560ef5ddc24ab47749a1f\
         1ffdbbb118f4e62fcfca3371b8fbfc5b0646b83e06bfbbab5fac30ea09ea2bc7\
         6f1ea568c9be0444b2cc90517b20ca825f2d0eccd88e7175538b85d90ab39018\
         3ca6395535d34473af6b5a5b88f5a59ee7561573337ea819da0dcc3573a22974",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = HmacDrbg::new(
        Hmac::new(Sha256Digest::new()),
        256,
        32,
        &mut rng,
        &nonce,
        &[],
    )
    .unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &first, &second, expected.len()),
        expected
    );
}

#[test]
fn hmac_sha512_without_additional_input_matches_cavp() {
    // drbgvectors_no_reseed/HMAC_DRBG.rsp, SHA-512, COUNT = 0.
    let entropy = hex("35049f389a33c0ecb1293238fd951f8ffd517dfde06041d32945b3e26914ba15");
    let nonce = hex("f7328760be6168e6aa9fb54784989a11");
    let expected = hex(
        "e76491b0260aacfded01ad39fbf1a66a88284caa5123368a2ad9330ee48335e3\
         c9c9ba90e6cbc9429962d60c1a6661edcfaa31d972b8264b9d4562cf18494128\
         a092c17a8da6f3113e8a7edfcd4427082bd390675e9662408144971717303d8dc\
         352c9e8b95e7f35fa2ac9f549b292bc7c4bc7f01ee0a577859ef6e82d79ef238\
         92d167c140d22aac32b64ccdfeee2730528a38763b24227f91ac3ffe47fb11538\
         e435307e77481802b0f613f370ffb0dbeab774fe1efbb1a80d01154a9459e73a\
         d361108bbc86b0914f095136cbe634555ce0bb263618dc5c367291ce082551898\
         7154fe9ecb052b3f0a256fcc30cc14572531c9628973639beda456f2bddf6",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = HmacDrbg::new(
        Hmac::new(Sha512Digest::new()),
        256,
        32,
        &mut rng,
        &nonce,
        &[],
    )
    .unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &[], &[], expected.len()),
        expected
    );
}

#[test]
fn hmac_sha512_with_additional_input_matches_cavp() {
    // drbgvectors_no_reseed/HMAC_DRBG.rsp, SHA-512, COUNT = 0, with additional input.
    let entropy = hex("a3da06bc88e2f2ea5181292c194a10b3db38a11d02ac2f9c65951d0c71f63e36");
    let nonce = hex("c74e5e3d7ba0193bcd6839e9ae93d70d");
    let first = hex("dbb7270760d8d262557807ce746ff314fd06598143611ab69bfc7e10ca5784b3");
    let second = hex("8cdea882f894e5fdc5f0a0b16b7d9ac8cde35ed17bcaf2665564d4ee74059e29");
    let expected = hex(
        "cb706b90e88380e5c1864458454027821b571dfeba0da83f712efb107b875209\
         9514ef87b4488fbfa3508a00954bb03090766d2bbd399e71c86c7967a4e8ded5\
         7095a29d4cfa01f8d28c97e81a4cd4fc5be7fb32a0d6c230cb8760e656b74fa\
         7e18e2063ebee5787958b272fc5de93f0d6837e55f0c360dc593c88fff30a428\
         cae37ded52f825646e04133a19790c304e4b1f040e10439c5edf454e6f71b23e\
         eb43cdbe7b0634b8e283a97806073f7f28a43de2d0d969b3eda380c185b785b\
         9101dc905025c9cdb499e594de0f0d3eb41922c20994fe2c403dd5bf01e4b2c3\
         ee6654d6ab9cca7d4d5ae59525a796119547eae6a3cbf8ad0e9b1de3c4d5a804e4",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = HmacDrbg::new(
        Hmac::new(Sha512Digest::new()),
        256,
        32,
        &mut rng,
        &nonce,
        &[],
    )
    .unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &first, &second, expected.len()),
        expected
    );
}

#[test]
fn hash_sha256_uses_the_440_bit_seed_length() {
    // drbgvectors_no_reseed/Hash_DRBG.rsp, SHA-256, COUNT = 0.
    let entropy = hex("a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb");
    let nonce = hex("8581f9317517276e06e9607ddbcbcc2e");
    let expected = hex(
        "d3e160c35b99f340b2628264d1751060e0045da383ff57a57d73a673d2b8d80d\
         aaf6a6c35a91bb4579d73fd0c8fed111b0391306828adfed528f018121b3febdc\
         343e797b87dbb63db1333ded9d1ece177cfa6b71fe8ab1da46624ed6415e51ccd\
         e2c7ca86e283990eeaeb91120415528b2295910281b02dd431f4c9f70427df",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = HashDrbg::new(Sha256Digest::new(), 256, 32, &mut rng, &nonce, &[]).unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &[], &[], expected.len()),
        expected
    );
}

#[test]
fn hash_sha512_uses_the_888_bit_seed_length() {
    // drbgvectors_no_reseed/Hash_DRBG.rsp, SHA-512, COUNT = 0.
    let entropy = hex("6b50a7d8f8a55d7a3df8bb40bcc3b722d8708de67fda010b03c4c84d72096f8c");
    let nonce = hex("3ec649cc6256d9fa31db7a2904aaf025");
    let expected = hex(
        "95b7f17e9802d3577392c6a9c08083b67dd1292265b5f42d237f1c55bb9b10b\
         fcfd82c77a378b8266a0099143b3c2d64611eeeb69acdc055957c139e8b190c7\
         a06955f2c797c2778de940396a501f40e91396acf8d7e45ebdbb53bbf8c97523\
         0d2f0ff9106c76119ae498e7fbc03d90f8e4c51627aed5c8d4263d5d2b97887\
         3a0de596ee6dc7f7c29e37eee8b34c90dd1cf6a9ddb22b4cbd086b14b35de93\
         da2d5cb1806698cbd7bbb67bfe3d31fd2d1dbd2a1e058a3eb99d7e51f1a938\
         eed5e1c1de23a6b4345d3191409f92f39b3670d8dbfb635d8e6a36932d81033\
         d1448d63b403ddf88e121b6e819ac381226c1321e4b08644f6727c368c5a9f7\
         a4b3ee2",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = HashDrbg::new(Sha512Digest::new(), 256, 32, &mut rng, &nonce, &[]).unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &[], &[], expected.len()),
        expected
    );
}

#[test]
fn ctr_aes128_with_df_matches_cavp() {
    // drbgvectors_no_reseed/CTR_DRBG.rsp, AES-128 use df, COUNT = 0.
    let entropy = hex("890eb067acf7382eff80b0c73bc872c6");
    let nonce = hex("aad471ef3ef1d203");
    let expected = hex(
        "a5514ed7095f64f3d0d3a5760394ab42062f373a25072a6ea6bcfd8489e94af6\
         cf18659fea22ed1ca0a9e33f718b115ee536b12809c31b72b08ddd8be1910fa3",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = CtrDrbg::new_with_derivation_function(
        AesEngine::new(),
        128,
        128,
        16,
        &mut rng,
        &nonce,
        &[],
    )
    .unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &[], &[], expected.len()),
        expected
    );
}

#[test]
fn ctr_aes256_with_df_matches_cavp() {
    // drbgvectors_no_reseed/CTR_DRBG.rsp, AES-256 use df, COUNT = 0.
    let entropy = hex("36401940fa8b1fba91a1661f211d78a0b9389a74e5bccfece8d766af1a6d3b14");
    let nonce = hex("496f25b0f1301b4f501be30380a137eb");
    let expected = hex(
        "5862eb38bd558dd978a696e6df164782ddd887e7e9a6c9f3f1fbafb78941b535\
         a64912dfd224c6dc7454e5250b3d97165e16260c2faf1cc7735cb75fb4f07e1d",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = CtrDrbg::new_with_derivation_function(
        AesEngine::new(),
        256,
        256,
        32,
        &mut rng,
        &nonce,
        &[],
    )
    .unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &[], &[], expected.len()),
        expected
    );
}

#[test]
fn ctr_aes256_without_df_matches_cavp() {
    // drbgvectors_no_reseed/CTR_DRBG.rsp, AES-256 no df, COUNT = 0.
    let entropy = hex(
        "df5d73faa468649edda33b5cca79b0b05600419ccb7a879ddfec9db32ee494e5\
         531b51de16a30f769262474c73bec010",
    );
    let expected = hex(
        "d1c07cd95af8a7f11012c84ce48bb8cb87189e99d40fccb1771c619bdf82ab22\
         80b1dc2f2581f39164f7ac0c510494b3a43c41b7db17514c87b107ae793e01c5",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = CtrDrbg::new_without_derivation_function(
        AesEngine::new(),
        256,
        256,
        48,
        &mut rng,
        &[],
        &[],
    )
    .unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &[], &[], expected.len()),
        expected
    );
}

#[test]
fn hmac_sha256_explicit_reseed_matches_pr_false_cavp() {
    // drbgvectors_pr_false/HMAC_DRBG.rsp, SHA-256, COUNT = 0.
    let mut entropy = hex("06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d");
    entropy.extend_from_slice(&hex(
        "01920a4e669ed3a85ae8a33b35a74ad7fb2a6bb4cf395ce00334a9c9a5a5d552",
    ));
    let nonce = hex("0e66f71edc43e42a45ad3c6fc6cdc4df");
    let expected = hex(
        "76fc79fe9b50beccc991a11b5635783a83536add03c157fb30645e611c2898bb\
         2b1bc215000209208cd506cb28da2a51bdb03826aaf2bd2335d576d519160842\
         e7158ad0949d1a9ec3e66ea1b1a064b005de914eac2e9d4f2d72a8616a80225\
         422918250ff66a41bd2f864a6a38cc5b6499dc43f7f2bd09e1e0f8f5885935124",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = HmacDrbg::new(
        Hmac::new(Sha256Digest::new()),
        256,
        32,
        &mut rng,
        &nonce,
        &[],
    )
    .unwrap();
    drbg.reseed(&mut rng, &[]).unwrap();

    assert_eq!(
        generate_twice(&mut drbg, &[], &[], expected.len()),
        expected
    );
}

#[test]
fn hash_sha512_explicit_prediction_resistance_matches_cavp() {
    // drbgvectors_pr_true/Hash_DRBG.rsp, SHA-512, COUNT = 0.
    let mut entropy = hex("73c9b115b7efb0a63244d7493ae5820599d7cee5ca054db2f7269ba7f621bdca");
    entropy.extend_from_slice(&hex(
        "cfcef3776b37649a7f6d2b48f443da79a2f2f81d04f3af9853a9e696c4487440",
    ));
    entropy.extend_from_slice(&hex(
        "d0638e28cae8d1c0f57209d677d889d195a672023cb8ade39f794989e1daee34",
    ));
    let nonce = hex("c204e6de789b0394fbbe6663466efcea");
    let expected = hex(
        "04744d1d42601995fa3b101ded3d2531cbf45afd83120d58eb26594a863bd831\
         8311b08d3df4c571a9c26dff63a3e9913a9a17a7c455186fdfdd90c664a84b73\
         a1106a5a82f741bd4c7a48bd046c268d8919efc941f8b45a3c3d89cf37141b5c\
         41b10ff543a6926272d623ad8eccd026552090adcfacb124f47c4ad62be90ea5\
         a0a7087d81458445813af88ffb5a8c3519f977131cc851cb4454b0a756c8373\
         f052382435ab934718c955177363389c06b0b5073478e84d253ff02a3f1bef1\
         bbf1338f77f92f029f638a4691c48c470d30d230f007f545e022f66c78a1306\
         97814aa55d2000a49553bef35fab5808e2f3cbb38c405611fa81444124e3f89e1e8",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = HashDrbg::new(Sha512Digest::new(), 256, 32, &mut rng, &nonce, &[]).unwrap();
    let mut output = vec![0_u8; expected.len()];
    drbg.reseed(&mut rng, &[]).unwrap();
    drbg.generate(&mut output, &[]).unwrap();
    drbg.reseed(&mut rng, &[]).unwrap();
    drbg.generate(&mut output, &[]).unwrap();

    assert_eq!(output, expected);
}

#[test]
fn ctr_aes128_explicit_prediction_resistance_matches_cavp() {
    // drbgvectors_pr_true/CTR_DRBG.rsp, AES-128 use df, COUNT = 0.
    let mut entropy = hex("5d4041942bcf68864a4997d8171f1f9f");
    entropy.extend_from_slice(&hex("ef55a769b7eaf03fe082029bb32a2b9d"));
    entropy.extend_from_slice(&hex("8239e865c0a42e14b964b9c09de85a20"));
    let nonce = hex("d4f1f4ae08bcb3e1");
    let expected = hex(
        "4155320287eedcf7d484c2c2a1e2eb64b9c9ce77c87202a1ae1616c7a5cfd1c6\
         87c7a0bfcc85bda48fdd4629fd330c22d0a76076f88fc7cd04037ee06b7af602",
    );
    let mut rng = FixedRng::new(entropy);
    let mut drbg = CtrDrbg::new_with_derivation_function(
        AesEngine::new(),
        128,
        128,
        16,
        &mut rng,
        &nonce,
        &[],
    )
    .unwrap();
    let mut output = vec![0_u8; expected.len()];
    drbg.reseed(&mut rng, &[]).unwrap();
    drbg.generate(&mut output, &[]).unwrap();
    drbg.reseed(&mut rng, &[]).unwrap();
    drbg.generate(&mut output, &[]).unwrap();

    assert_eq!(output, expected);
}
