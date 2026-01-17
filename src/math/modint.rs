use crate::errors::Result;
use crate::math::BigUint;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModInt {
    v: BigUint,
    m: BigUint,
}

impl ModInt {
    pub fn new(v: BigUint, mut m: BigUint) -> Result<Self> {
        // IMPORTANT: normalize modulus so it has canonical limb length.
        // This matters for fast prime reduction checks (secp256k1 p).
        m.normalize();
        Ok(Self {
            v: v.mod_reduce(&m),
            m,
        })
    }

    pub fn value(&self) -> &BigUint {
        &self.v
    }

    pub fn add(&self, other: &ModInt) -> Result<ModInt> {
        Ok(ModInt::new(self.v.add(&other.v), self.m.clone())?)
    }

    pub fn sub(&self, other: &ModInt) -> Result<ModInt> {
        Ok(ModInt::new(
            self.v.sub_mod(&other.v, &self.m),
            self.m.clone(),
        )?)
    }

    pub fn mul(&self, other: &ModInt) -> Result<ModInt> {
        Ok(ModInt::new(self.v.mul(&other.v), self.m.clone())?)
    }

    pub fn inv(&self) -> Result<ModInt> {
        let inv = self.v.modinv(&self.m)?;
        Ok(ModInt::new(inv, self.m.clone())?)
    }
}
