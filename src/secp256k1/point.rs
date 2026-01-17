//! Elliptic curve point operations for secp256k1.
//!
//! Public API stays affine `Point {x,y,infinity}`.
//! Internally uses Jacobian coordinates for speed.
//!
//! Includes a window-4 scalar multiply optimized for generator multiplication.

use crate::errors::Result;
use crate::math::{BigUint, ModInt};

use super::curve::{secp256k1_a, secp256k1_prime_p};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
    pub infinity: bool,
}

impl Point {
    pub fn infinity() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::zero(),
            infinity: true,
        }
    }

    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.infinity
    }

    pub fn on_curve(&self) -> Result<bool> {
        if self.infinity {
            return Ok(true);
        }

        let p = secp256k1_prime_p();
        let a = secp256k1_a();
        let b = BigUint::from_u64(7);

        let x = ModInt::new(self.x.clone(), p.clone())?;
        let y = ModInt::new(self.y.clone(), p.clone())?;

        let y2 = y.mul(&y)?;
        let x2 = x.mul(&x)?;
        let x3 = x2.mul(&x)?;
        let ax = ModInt::new(a, p.clone())?.mul(&x)?;
        let rhs = x3.add(&ax)?.add(&ModInt::new(b, p.clone())?)?;

        Ok(y2.value() == rhs.value())
    }

    /// Public point addition: uses Jacobian internally (fast, avoids repeated inversions).
    pub fn add(&self, other: &Point) -> Result<Point> {
        if self.infinity {
            return Ok(other.clone());
        }
        if other.infinity {
            return Ok(self.clone());
        }
        let p = secp256k1_prime_p();
        let j1 = JacobianPoint::from_affine(self, p.clone())?;
        let j2 = JacobianPoint::from_affine(other, p.clone())?;
        j1.add(&j2)?.to_affine()
    }

    /// Scalar multiplication (generic): Jacobian double-and-add.
    pub fn mul_scalar(&self, mut k: BigUint) -> Result<Point> {
        if self.infinity || k.is_zero() {
            return Ok(Point::infinity());
        }

        let p = secp256k1_prime_p();
        let mut addend = JacobianPoint::from_affine(self, p.clone())?;
        let mut result = JacobianPoint::infinity(p.clone())?;

        while !k.is_zero() {
            if k.is_odd() {
                result = result.add(&addend)?;
            }
            addend = addend.double()?;
            k.shr1_assign();
        }

        result.to_affine()
    }

    /// Faster multiplication using a 4-bit window (nibble method).
    ///
    /// Recommended for generator multiplication in ECDSA: k*G.
    pub fn mul_scalar_window4(&self, k: &BigUint) -> Result<Point> {
        if self.infinity || k.is_zero() {
            return Ok(Point::infinity());
        }

        let p = secp256k1_prime_p();

        // Precompute table[0..15] where table[i] = i*self
        let base = JacobianPoint::from_affine(self, p.clone())?;
        let mut table: Vec<JacobianPoint> = Vec::with_capacity(16);
        table.push(JacobianPoint::infinity(p.clone())?);
        table.push(base.clone());
        for i in 2..16 {
            let next = table[i - 1].add(&base)?;
            table.push(next);
        }

        let bytes = k.to_be_bytes_fixed(32);
        let mut acc = JacobianPoint::infinity(p.clone())?;

        for &b in &bytes {
            let hi = (b >> 4) as usize;
            let lo = (b & 0x0f) as usize;

            acc = acc.double_n(4)?;
            if hi != 0 {
                acc = acc.add(&table[hi])?;
            }

            acc = acc.double_n(4)?;
            if lo != 0 {
                acc = acc.add(&table[lo])?;
            }
        }

        acc.to_affine()
    }
}

#[derive(Clone, Debug)]
struct JacobianPoint {
    x: ModInt,
    y: ModInt,
    z: ModInt,
    p: BigUint,
}

impl JacobianPoint {
    fn infinity(p: BigUint) -> Result<Self> {
        Ok(Self {
            x: ModInt::new(BigUint::zero(), p.clone())?,
            y: ModInt::new(BigUint::one(), p.clone())?,
            z: ModInt::new(BigUint::zero(), p.clone())?, // Z=0 => infinity
            p,
        })
    }

    fn is_infinity(&self) -> bool {
        self.z.value().is_zero()
    }

    fn from_affine(pt: &Point, p: BigUint) -> Result<Self> {
        if pt.infinity {
            return Self::infinity(p);
        }
        Ok(Self {
            x: ModInt::new(pt.x.clone(), p.clone())?,
            y: ModInt::new(pt.y.clone(), p.clone())?,
            z: ModInt::new(BigUint::one(), p.clone())?,
            p,
        })
    }

    fn to_affine(&self) -> Result<Point> {
        if self.is_infinity() {
            return Ok(Point::infinity());
        }

        // One inversion at end
        let zinv = self.z.inv()?;
        let zinv2 = zinv.mul(&zinv)?;
        let zinv3 = zinv2.mul(&zinv)?;

        let x = self.x.mul(&zinv2)?.value().clone();
        let y = self.y.mul(&zinv3)?.value().clone();

        Ok(Point::new(x, y))
    }

    fn double_n(&self, n: usize) -> Result<Self> {
        let mut r = self.clone();
        for _ in 0..n {
            r = r.double()?;
        }
        Ok(r)
    }

    fn double(&self) -> Result<Self> {
        if self.is_infinity() {
            return Ok(self.clone());
        }

        // secp256k1: a = 0
        let p = self.p.clone();

        let two = ModInt::new(BigUint::from_u64(2), p.clone())?;
        let three = ModInt::new(BigUint::from_u64(3), p.clone())?;
        let four = ModInt::new(BigUint::from_u64(4), p.clone())?;
        let eight = ModInt::new(BigUint::from_u64(8), p.clone())?;

        let y2 = self.y.mul(&self.y)?; // Y^2
        let x2 = self.x.mul(&self.x)?; // X^2
        let s = four.mul(&self.x)?.mul(&y2)?; // 4*X*Y^2
        let m = three.mul(&x2)?; // 3*X^2

        let x3 = m.mul(&m)?.sub(&two.mul(&s)?)?;
        let y4 = y2.mul(&y2)?;
        let y3 = m.mul(&s.sub(&x3)?)?.sub(&eight.mul(&y4)?)?;
        let z3 = two.mul(&self.y)?.mul(&self.z)?;

        Ok(Self {
            x: x3,
            y: y3,
            z: z3,
            p,
        })
    }

    fn add(&self, other: &Self) -> Result<Self> {
        if self.is_infinity() {
            return Ok(other.clone());
        }
        if other.is_infinity() {
            return Ok(self.clone());
        }

        let p = self.p.clone();
        let two = ModInt::new(BigUint::from_u64(2), p.clone())?;

        let z1z1 = self.z.mul(&self.z)?;
        let z2z2 = other.z.mul(&other.z)?;

        let u1 = self.x.mul(&z2z2)?;
        let u2 = other.x.mul(&z1z1)?;

        let z1z1z1 = z1z1.mul(&self.z)?;
        let z2z2z2 = z2z2.mul(&other.z)?;

        let s1 = self.y.mul(&z2z2z2)?;
        let s2 = other.y.mul(&z1z1z1)?;

        let h = u2.sub(&u1)?;
        let r = s2.sub(&s1)?;

        if h.value().is_zero() {
            if r.value().is_zero() {
                return self.double();
            }
            return JacobianPoint::infinity(p);
        }

        let hh = h.mul(&h)?;
        let hhh = hh.mul(&h)?;
        let u1hh = u1.mul(&hh)?;

        let x3 = r.mul(&r)?.sub(&hhh)?.sub(&two.mul(&u1hh)?)?;
        let y3 = r.mul(&u1hh.sub(&x3)?)?.sub(&s1.mul(&hhh)?)?;
        let z3 = h.mul(&self.z)?.mul(&other.z)?;

        Ok(Self {
            x: x3,
            y: y3,
            z: z3,
            p,
        })
    }
}
