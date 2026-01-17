// src/math/bigint.rs
use crate::errors::{Error, Result};
use core::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    // Little-endian limbs: limbs[0] is least-significant 32 bits
    limbs: Vec<u32>,
}

/* =========================
 * Ordering (correct for LE)
 * ========================= */
impl BigUint {
    #[inline]
    fn norm_len(&self) -> usize {
        let mut i = self.limbs.len();
        while i > 0 && self.limbs[i - 1] == 0 {
            i -= 1;
        }
        i
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.norm_len();
        let b = other.norm_len();
        match a.cmp(&b) {
            Ordering::Equal => {}
            o => return o,
        }
        for i in (0..a).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/* =========================
 * Constructors / basics
 * ========================= */
impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: vec![] }
    }

    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    pub fn from_u64(mut x: u64) -> Self {
        if x == 0 {
            return Self::zero();
        }
        let mut limbs = Vec::new();
        while x > 0 {
            limbs.push((x & 0xffff_ffff) as u32);
            x >>= 32;
        }
        let mut r = Self { limbs };
        r.normalize();
        r
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::zero();
        }
        let mut limbs = Vec::new();
        let mut i = bytes.len();
        while i > 0 {
            let start = i.saturating_sub(4);
            let mut chunk = [0u8; 4];
            chunk[4 - (i - start)..].copy_from_slice(&bytes[start..i]);
            limbs.push(u32::from_be_bytes(chunk));
            i = start;
        }
        let mut r = Self { limbs };
        r.normalize();
        r
    }

    pub fn is_zero(&self) -> bool {
        self.norm_len() == 0
    }

    pub fn is_even(&self) -> bool {
        self.is_zero() || (self.limbs[0] & 1) == 0
    }

    pub fn is_odd(&self) -> bool {
        !self.is_zero() && (self.limbs[0] & 1) == 1
    }

    pub fn normalize(&mut self) {
        while let Some(&last) = self.limbs.last() {
            if last == 0 {
                self.limbs.pop();
            } else {
                break;
            }
        }
    }

    pub fn bit_len(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let last = *self.limbs.last().unwrap();
        32 * (self.limbs.len() - 1) + (32 - last.leading_zeros() as usize)
    }
}

/* =========================
 * Encoding helpers
 * ========================= */
impl BigUint {
    /// Big-endian minimal bytes. Returns [0] for zero.
    pub fn to_be_bytes_minimal(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0u8];
        }
        let mut out = Vec::with_capacity(self.limbs.len() * 4);
        for &limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        while out.len() > 1 && out[0] == 0 {
            out.remove(0);
        }
        out
    }

    /// Big-endian fixed-length bytes, left padded with zeros.
    pub fn to_be_bytes_fixed(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let b = self.to_be_bytes_minimal();
        if b.len() >= len {
            out.copy_from_slice(&b[b.len() - len..]);
        } else {
            out[len - b.len()..].copy_from_slice(&b);
        }
        out
    }
}

/* =========================
 * Shifts
 * ========================= */
impl BigUint {
    pub fn shl1_assign(&mut self) {
        if self.is_zero() {
            return;
        }
        let mut carry = 0u32;
        for limb in self.limbs.iter_mut() {
            let new_carry = (*limb >> 31) & 1;
            *limb = (*limb << 1) | carry;
            carry = new_carry;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
        self.normalize();
    }

    pub fn shr1_assign(&mut self) {
        if self.is_zero() {
            return;
        }
        let mut carry = 0u32;
        for i in (0..self.limbs.len()).rev() {
            let new_carry = self.limbs[i] & 1;
            self.limbs[i] = (self.limbs[i] >> 1) | (carry << 31);
            carry = new_carry;
        }
        self.normalize();
    }

    pub fn shl_bits(&self, bits: usize) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let limb_shift = bits / 32;
        let bit_shift = bits % 32;

        let mut out = vec![0u32; limb_shift + self.limbs.len() + 1];
        let mut carry = 0u32;

        for (i, &limb) in self.limbs.iter().enumerate() {
            if bit_shift == 0 {
                out[limb_shift + i] = limb;
            } else {
                let x = ((limb as u64) << bit_shift) | (carry as u64);
                out[limb_shift + i] = (x & 0xffff_ffff) as u32;
                carry = (x >> 32) as u32;
            }
        }

        if bit_shift != 0 {
            out[limb_shift + self.limbs.len()] = carry;
        }

        let mut r = Self { limbs: out };
        r.normalize();
        r
    }

    pub fn shr_bits(&self, bits: usize) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let limb_shift = bits / 32;
        let bit_shift = bits % 32;

        if limb_shift >= self.limbs.len() {
            return Self::zero();
        }

        if bit_shift == 0 {
            let out = self.limbs[limb_shift..].to_vec();
            let mut r = Self { limbs: out };
            r.normalize();
            return r;
        }

        // Correct bit-shift right across limbs (LE)
        let mut out = vec![0u32; self.limbs.len() - limb_shift];
        let mut carry = 0u32;

        for out_i_rev in (0..out.len()).rev() {
            let i = out_i_rev + limb_shift;
            let limb = self.limbs[i];
            out[out_i_rev] = (limb >> bit_shift) | (carry << (32 - bit_shift));
            carry = limb;
        }

        let mut r = Self { limbs: out };
        r.normalize();
        r
    }
}

/* =========================
 * Arithmetic (add/sub/mul)
 * ========================= */
impl BigUint {
    pub fn add(&self, other: &Self) -> Self {
        let n = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry: u64 = 0;

        for i in 0..n {
            let a = *self.limbs.get(i).unwrap_or(&0) as u64;
            let b = *other.limbs.get(i).unwrap_or(&0) as u64;
            let sum = a + b + carry;
            out.push((sum & 0xffff_ffff) as u32);
            carry = sum >> 32;
        }

        if carry != 0 {
            out.push(carry as u32);
        }

        let mut r = Self { limbs: out };
        r.normalize();
        r
    }

    pub fn sub(&self, other: &Self) -> Result<Self> {
        if self < other {
            return Err(Error::InvalidInput("underflow in BigUint::sub"));
        }

        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow: i64 = 0;

        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i64;
            let b = *other.limbs.get(i).unwrap_or(&0) as i64;
            let mut v = a - b - borrow;
            if v < 0 {
                v += 1i64 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(v as u32);
        }

        let mut r = Self { limbs: out };
        r.normalize();
        Ok(r)
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        let mut out = vec![0u64; self.limbs.len() + other.limbs.len()];

        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let idx = i + j;
                let t = out[idx] + (a as u64) * (b as u64) + carry;
                out[idx] = t & 0xffff_ffff;
                carry = t >> 32;
            }
            out[i + other.limbs.len()] += carry;
        }

        let limbs = out.into_iter().map(|x| x as u32).collect();
        let mut r = Self { limbs };
        r.normalize();
        r
    }
}

/* =========================
 * Modular arithmetic
 * ========================= */
impl BigUint {
    pub fn mod_reduce(&self, m: &Self) -> Self {
        if m.is_zero() {
            return Self::zero();
        }
        let (_q, r) = self.divmod(m).unwrap();
        r
    }

    pub fn sub_mod(&self, other: &Self, m: &Self) -> Self {
        if m.is_zero() {
            return Self::zero();
        }
        let a = self.mod_reduce(m);
        let b = other.mod_reduce(m);

        if a >= b {
            a.sub(&b).unwrap()
        } else {
            a.add(m).sub(&b).unwrap()
        }
    }

    pub fn mul_mod(&self, other: &Self, m: &Self) -> Self {
        self.mul(other).mod_reduce(m)
    }

    pub fn modinv(&self, m: &Self) -> Result<Self> {
        crate::math::euclid::modinv(self, m)
    }
}

/* =========================
 * Division
 * ========================= */
impl BigUint {
    pub fn divmod(&self, other: &Self) -> Result<(Self, Self)> {
        if other.is_zero() {
            return Err(Error::InvalidInput("division by zero"));
        }
        if self < other {
            return Ok((Self::zero(), self.clone()));
        }

        let mut q = Self::zero();
        let mut r = self.clone();

        let mut denom = other.clone();
        let mut shift = r.bit_len().saturating_sub(denom.bit_len());
        denom = denom.shl_bits(shift);

        loop {
            if r >= denom {
                r = r.sub(&denom)?;
                q = q.set_bit(shift);
            }
            if shift == 0 {
                break;
            }
            denom = denom.shr_bits(1);
            shift -= 1;
        }

        Ok((q, r))
    }

    pub fn set_bit(mut self, bit: usize) -> Self {
        let limb = bit / 32;
        let off = bit % 32;
        if self.limbs.len() <= limb {
            self.limbs.resize(limb + 1, 0);
        }
        self.limbs[limb] |= 1u32 << off;
        self
    }
}
