//! Public key encoding (SEC) and hash160 helper.

use crate::crypto::{ripemd160::ripemd160, sha256::sha256};
use crate::errors::{Error, Result};

use super::point::Point;

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub point: Point,
}

impl PublicKey {
    pub fn from_point(point: Point) -> Self {
        Self { point }
    }

    /// Derive public key from secret scalar: Q = d*G
    pub fn from_secret_key(secret_key: &crate::math::BigUint) -> Result<Self> {
        let (gx, gy) = super::curve::secp256k1_generator();
        let g = Point::new(gx, gy);
        let q = g.mul_scalar(secret_key.clone())?;
        Ok(Self::from_point(q))
    }

    /// SEC encoding (compressed/uncompressed).
    pub fn encode_sec(&self, compressed: bool) -> Result<Vec<u8>> {
        if self.point.infinity {
            return Err(Error::InvalidInput("cannot encode point at infinity"));
        }

        let x = self.point.x.to_be_bytes_fixed(32);
        let y = self.point.y.to_be_bytes_fixed(32);

        if compressed {
            let prefix = if self.point.y.is_even() {
                0x02u8
            } else {
                0x03u8
            };
            let mut out = Vec::with_capacity(33);
            out.push(prefix);
            out.extend_from_slice(&x);
            Ok(out)
        } else {
            let mut out = Vec::with_capacity(65);
            out.push(0x04u8);
            out.extend_from_slice(&x);
            out.extend_from_slice(&y);
            Ok(out)
        }
    }

    /// hash160 = RIPEMD160(SHA256(sec_bytes))
    pub fn hash160(&self, compressed: bool) -> Result<Vec<u8>> {
        let sec = self.encode_sec(compressed)?;
        let h1 = sha256(&sec);
        let h2 = ripemd160(&h1);
        Ok(h2.to_vec())
    }
}
