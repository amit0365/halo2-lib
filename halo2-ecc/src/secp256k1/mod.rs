use halo2_base::gates::RangeChip;
use halo2_base::halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;
use halo2_base::halo2_proofs::halo2curves::CurveAffine;
use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint, BigPrimeField, modulus};
use halo2_base::Context;
use rand::rngs::StdRng;

use crate::ecc::ecdsa::ecdsa_verify_no_pubkey_check;
use crate::halo2_proofs::halo2curves::secp256k1::{Fp, Fq};

use crate::ecc::{self, EccChip};
use crate::fields::{fp, FieldChip};

pub type FpChip<'range, F> = fp::FpChip<'range, F, Fp>;
pub type FqChip<'range, F> = fp::FpChip<'range, F, Fq>;
pub type Secp256k1Chip<'chip, F> = ecc::EccChip<'chip, F, FpChip<'chip, F>>;
pub const SECP_B: u64 = 7;

#[derive(Clone, Copy, Debug)]
pub struct ECDSAInput {
    pub r: Fq,
    pub s: Fq,
    pub msghash: Fq,
    pub pk: Secp256k1Affine,
}

pub fn random_ecdsa_input(rng: &mut StdRng) -> ECDSAInput {
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(rng.clone());
    let pk = Secp256k1Affine::from(Secp256k1Affine::generator() * sk);
    let msghash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(rng.clone());

    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(rng);
    let k_inv = k.invert().unwrap();

    let r_point = Secp256k1Affine::from(Secp256k1Affine::generator() * k).coordinates().unwrap();
    let x = r_point.x();
    let x_bigint = fe_to_biguint(x);
    let r = biguint_to_fe::<Fq>(&(x_bigint % modulus::<Fq>()));
    let s = k_inv * (msghash + (r * sk));

    ECDSAInput { r, s, msghash, pk }
}

pub fn ecdsa<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    input: ECDSAInput,
    limb_bits: usize,
    num_limbs: usize,
) -> F {
    let fp_chip = FpChip::<F>::new(range, limb_bits, num_limbs);
    let fq_chip = FqChip::<F>::new(range, limb_bits, num_limbs);

    let [m, r, s] = [input.msghash, input.r, input.s].map(|x| fq_chip.load_private(ctx, x));

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pk = ecc_chip.load_private_unchecked(ctx, (input.pk.x, input.pk.y));
    // test ECDSA
    let res = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );
    *res.value()
}

#[cfg(test)]
mod tests;
