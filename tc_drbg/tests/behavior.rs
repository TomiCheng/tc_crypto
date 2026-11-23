use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use tc_aes::AesEngine;
use tc_drbg::{CtrDrbg, Drbg, DrbgError, HashDrbg};
use tc_sha::Sha256Digest;

struct FixedRng {
    byte: u8,
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
        output.fill(self.byte);
        self.byte = self.byte.wrapping_add(1);
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

#[test]
fn reseed_changes_the_output_stream() {
    let mut first_rng = FixedRng { byte: 1 };
    let mut second_rng = FixedRng { byte: 1 };
    let mut without_reseed = HashDrbg::new(
        Sha256Digest::new(),
        256,
        32,
        &mut first_rng,
        &[2_u8; 16],
        &[],
    )
    .unwrap();
    let mut with_reseed = HashDrbg::new(
        Sha256Digest::new(),
        256,
        32,
        &mut second_rng,
        &[2_u8; 16],
        &[],
    )
    .unwrap();
    with_reseed.reseed(&mut second_rng, &[]).unwrap();

    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    without_reseed.generate(&mut first, &[]).unwrap();
    with_reseed.generate(&mut second, &[]).unwrap();
    assert_ne!(first, second);
}

#[test]
fn request_larger_than_the_sp800_limit_is_rejected() {
    let mut rng = FixedRng { byte: 1 };
    let mut drbg = HashDrbg::new(Sha256Digest::new(), 256, 32, &mut rng, &[2_u8; 16], &[]).unwrap();
    let mut output = vec![0_u8; 32_769];

    assert_eq!(
        drbg.generate(&mut output, &[]),
        Err(DrbgError::RequestTooLarge {
            requested: 32_769,
            maximum: 32_768,
        })
    );
}

#[test]
fn ctr_without_df_rejects_the_wrong_seed_material_length() {
    let mut rng = FixedRng { byte: 1 };
    let result = CtrDrbg::new_without_derivation_function(
        AesEngine::new(),
        256,
        256,
        47,
        &mut rng,
        &[],
        &[],
    );

    assert!(matches!(
        result,
        Err(DrbgError::InvalidSeedLength {
            expected: 48,
            actual: 47,
        })
    ));
}

#[test]
fn ctr_with_df_accepts_aes192() {
    let mut rng = FixedRng { byte: 1 };
    let mut drbg = CtrDrbg::new_with_derivation_function(
        AesEngine::new(),
        192,
        192,
        24,
        &mut rng,
        &[2_u8; 12],
        &[],
    )
    .unwrap();

    drbg.generate(&mut [0_u8; 41], &[]).unwrap();
}

#[test]
fn rng_and_generate_without_additional_input_are_identical() {
    let mut first_rng = FixedRng { byte: 1 };
    let mut second_rng = FixedRng { byte: 1 };
    let mut direct = HashDrbg::new(
        Sha256Digest::new(),
        256,
        32,
        &mut first_rng,
        &[2_u8; 16],
        &[],
    )
    .unwrap();
    let mut through_rng = HashDrbg::new(
        Sha256Digest::new(),
        256,
        32,
        &mut second_rng,
        &[2_u8; 16],
        &[],
    )
    .unwrap();

    let mut direct_output = [0_u8; 64];
    let mut rng_output = [0_u8; 64];
    direct.generate(&mut direct_output, &[]).unwrap();
    through_rng.try_fill_bytes(&mut rng_output).unwrap();
    assert_eq!(direct_output, rng_output);
}

#[test]
fn entropy_is_buffered_up_to_256_bytes() {
    let mut rng = FixedRng { byte: 1 };
    let mut drbg =
        HashDrbg::new(Sha256Digest::new(), 256, 256, &mut rng, &[2_u8; 16], &[]).unwrap();
    drbg.reseed(&mut rng, &[3_u8; 300]).unwrap();
    drbg.generate(&mut [0_u8; 32], &[]).unwrap();

    let result = HashDrbg::new(Sha256Digest::new(), 256, 257, &mut rng, &[2_u8; 16], &[]);
    assert!(matches!(
        result,
        Err(DrbgError::ExcessiveEntropy {
            maximum: 256,
            provided: 257,
        })
    ));
}
