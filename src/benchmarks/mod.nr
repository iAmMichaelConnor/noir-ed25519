use crate::ed25519_verify;
use edwards_bignum::ed25519::Ed25519;
use edwards_bignum::ScalarField;

#[export]
fn bench_ed25519_verify_32(
    pubkey: Ed25519,
    sig_scalar: ScalarField<64>,
    sig_point: Ed25519,
    message: BoundedVec<u8, 32>,
) -> bool {
    ed25519_verify(pubkey, sig_scalar, sig_point, message)
}

#[export]
fn bench_ed25519_verify_128(
    pubkey: Ed25519,
    sig_scalar: ScalarField<64>,
    sig_point: Ed25519,
    message: BoundedVec<u8, 128>,
) -> bool {
    ed25519_verify(pubkey, sig_scalar, sig_point, message)
}
