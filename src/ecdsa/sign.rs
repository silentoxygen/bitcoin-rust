//! ECDSA signing (secp256k1) with RFC6979 deterministic k.
//!
//! This file is bounded (won't hang forever).
//! Uses a faster window-4 scalar multiplication for k*G.

use crate::crypto::hmac_sha256::hmac_sha256;
use crate::errors::{Error, Result};
use crate::math::BigUint;
use crate::secp256k1::curve::{secp256k1_generator, secp256k1_order_n};
use crate::secp256k1::point::Point;

use super::signature::Signature;

pub fn sign_message(secret_key: &BigUint, msg: &[u8]) -> Result<Signature> {
    use crate::crypto::sha256::sha256;
    let d = sha256(&sha256(msg));
    sign_digest(secret_key, &d)
}

pub fn sign_digest(secret_key: &BigUint, digest32: &[u8; 32]) -> Result<Signature> {
    let mut n = secp256k1_order_n();
    n.normalize();

    if secret_key.is_zero() {
        return Err(Error::InvalidInput("secret key is zero"));
    }

    let z = BigUint::from_be_bytes(digest32).mod_reduce(&n);

    // RFC6979
    let x = secret_key.to_be_bytes_fixed(32);
    let h1 = z.to_be_bytes_fixed(32);

    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];

    let mut tmp = Vec::with_capacity(32 + 1 + 32 + 32);
    tmp.extend_from_slice(&v);
    tmp.push(0x00);
    tmp.extend_from_slice(&x);
    tmp.extend_from_slice(&h1);
    k = hmac_sha256(&k, &tmp)?;

    v = hmac_sha256(&k, &v)?;

    let mut tmp2 = Vec::with_capacity(32 + 1 + 32 + 32);
    tmp2.extend_from_slice(&v);
    tmp2.push(0x01);
    tmp2.extend_from_slice(&x);
    tmp2.extend_from_slice(&h1);
    k = hmac_sha256(&k, &tmp2)?;

    v = hmac_sha256(&k, &v)?;

    for _ in 0..512 {
        v = hmac_sha256(&k, &v)?;

        let cand = BigUint::from_be_bytes(&v).mod_reduce(&n);

        if !cand.is_zero() && cand < n {
            return sign_with_k(secret_key, &z, &cand, &n);
        }

        let mut t = Vec::with_capacity(32 + 1);
        t.extend_from_slice(&v);
        t.push(0x00);
        k = hmac_sha256(&k, &t)?;
        v = hmac_sha256(&k, &v)?;
    }

    Err(Error::InvalidInput(
        "RFC6979 failed to generate valid k (bounded loop exceeded)",
    ))
}

fn sign_with_k(secret_key: &BigUint, z: &BigUint, k: &BigUint, n: &BigUint) -> Result<Signature> {
    // Use windowed multiplication for generator
    let (gx, gy) = secp256k1_generator();
    let g = Point::new(gx, gy);

    // R = k*G (fast)
    let r_point = g.mul_scalar_window4(k)?;

    let r = r_point.x.mod_reduce(n);
    if r.is_zero() {
        return Err(Error::InvalidInput("r is zero"));
    }

    // s = k^{-1} * (z + r*secret) mod n
    let kinv = k.modinv(n)?;
    let rs = r.mul_mod(secret_key, n);
    let sum = z.add(&rs).mod_reduce(n);
    let mut s = kinv.mul_mod(&sum, n);
    if s.is_zero() {
        return Err(Error::InvalidInput("s is zero"));
    }

    // low-s
    let mut half_n = n.clone();
    half_n.shr1_assign();
    if s > half_n {
        s = n.sub(&s)?;
    }

    Ok(Signature { r, s })
}
