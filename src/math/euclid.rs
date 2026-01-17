//! Binary extended GCD modular inverse (Stein's algorithm).
//!
//! Correct odd-handling is critical:
//!   if x is odd: x = (x + m) / 2
//! NOT: (x + m) mod m, which breaks the algorithm.

use crate::errors::{Error, Result};
use crate::math::BigUint;

/// Binary modular inverse: returns a^{-1} mod m, assuming gcd(a,m)=1.
/// Requires m odd (true for secp256k1 field prime and curve order n).
pub fn modinv(a: &BigUint, m: &BigUint) -> Result<BigUint> {
    if m.is_zero() {
        return Err(Error::InvalidInput("modinv modulus is zero"));
    }
    if m.is_even() {
        return Err(Error::InvalidInput("modinv requires odd modulus"));
    }

    let mut u = a.mod_reduce(m);
    if u.is_zero() {
        return Err(Error::InvalidInput("modinv of zero"));
    }
    let mut v = m.clone();

    // x1 tracks inverse of u, x2 tracks inverse of v, both in [0, m)
    let mut x1 = BigUint::one();
    let mut x2 = BigUint::zero();

    while u != BigUint::one() && v != BigUint::one() {
        while u.is_even() {
            u.shr1_assign();
            if x1.is_even() {
                x1.shr1_assign();
            } else {
                // x1 = (x1 + m) / 2
                let mut t = x1.add(m);
                t.shr1_assign();
                x1 = t;
                // Note: since x1<m and m odd, (x1+m)/2 < m always.
            }
        }

        while v.is_even() {
            v.shr1_assign();
            if x2.is_even() {
                x2.shr1_assign();
            } else {
                // x2 = (x2 + m) / 2
                let mut t = x2.add(m);
                t.shr1_assign();
                x2 = t;
            }
        }

        if u >= v {
            u = u.sub(&v)?;
            x1 = x1.sub_mod(&x2, m);
        } else {
            v = v.sub(&u)?;
            x2 = x2.sub_mod(&x1, m);
        }
    }

    if u == BigUint::one() {
        Ok(x1.mod_reduce(m))
    } else {
        Ok(x2.mod_reduce(m))
    }
}
