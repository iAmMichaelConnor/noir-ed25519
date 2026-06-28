use std::ops::Neg;

use bignum::{bignum::BigNum, ED25519_Fr as Fr};
use edwards_bignum::{CurveTrait, ScalarField, TECurveParameterTrait};
use edwards_bignum::ed25519::{Ed25519, Ed25519Params};
use sha512::sha512;

pub fn ed25519_verify<let MSG_MAX_LEN: u32>(
    pubkey: Ed25519,
    sig_scalar: ScalarField<64>,
    sig_point: Ed25519,
    message: BoundedVec<u8, MSG_MAX_LEN>,
) -> bool {
    pubkey.assert_is_on_curve();
    sig_point.assert_is_on_curve();

    // Reject small-order / identity public keys: 8A == O iff ord(A) divides the
    // cofactor (8), so this rules out all torsion-only keys, for which the check
    // below would otherwise hold for any message.
    assert(!pubkey.dbl().dbl().dbl().is_zero());

    let mut preimage: BoundedVec<u8, 32 + 32 + MSG_MAX_LEN> = BoundedVec::new();
    preimage.extend_from_array(compress(sig_point));
    preimage.extend_from_array(compress(pubkey));
    preimage.extend_from_bounded_vec(message);

    let k = reduce_wide(sha512::sha512_var(preimage));

    // Check the cofactored group equation [8][s]B == [8]R + [8][k]A
    // (RFC 8032 5.1.7), rewritten as [8]([s]B + [k](-A)) == [8]R so the two
    // scalar multiplications share a single doubling ladder via an MSM.
    //
    // Multiplying both sides by the cofactor (8 = three doublings) clears any
    // order-8 torsion component in A or R.
    let basepoint = Ed25519::from(Ed25519Params::gen());
    let lhs = Ed25519::msm([basepoint, pubkey.neg()], [sig_scalar, k]);
    lhs.dbl().dbl().dbl() == sig_point.dbl().dbl().dbl()
}

/// Encode an Ed25519 point into its 32-byte compressed form (RFC 8032 5.1.2):
/// the little-endian y-coordinate with the low bit of x stored in the most
/// significant bit. Valid points have y < 2^255, so that bit is always free.
pub fn compress(point: Ed25519) -> [u8; 32] {
    let mut enc: [u8; 32] = point.y.to_le_bytes();
    let x_bytes: [u8; 32] = point.x.to_le_bytes();
    let x_sign = x_bytes[0] & 1;
    enc[31] = enc[31] | (x_sign << 7);
    enc
}

/// Reduce a 64-byte little-endian integer (the SHA-512 digest) modulo the
/// Ed25519 group order, returning it as a curve scalar.
///
/// Uses Horner's method over 32-bit words in the scalar field Fr
/// so the wide value is reduced as it is accumulated.
fn reduce_wide(bytes: [u8; 64]) -> ScalarField<64> {
    let base = Fr::from_limbs([0x100000000, 0, 0]); // 2^32
    let mut acc = Fr::zero();
    for i in 0..16 {
        let j = 15 - i; // most-significant 32-bit word first
        let word = (bytes[4 * j] as u128)
            + (bytes[4 * j + 1] as u128) * 0x100
            + (bytes[4 * j + 2] as u128) * 0x10000
            + (bytes[4 * j + 3] as u128) * 0x1000000;
        acc = acc * base + Fr::from_limbs([word, 0, 0]);
    }

    // acc is reduced mod ell (< 2^253), so it fits in a single field element.
    let limbs = acc.get_limbs();
    let p120: Field = 0x1000000000000000000000000000000; // 2^120
    let k_field =
        limbs[0] as Field + (limbs[1] as Field) * p120 + (limbs[2] as Field) * p120 * p120;
    ScalarField::<64>::from(k_field)
}

mod test;
mod benchmarks;
