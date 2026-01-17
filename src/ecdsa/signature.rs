//! ECDSA signature (r,s) and DER encoding/decoding.

use crate::errors::{Error, Result};
use crate::math::BigUint;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: BigUint,
    pub s: BigUint,
}

impl Signature {
    pub fn new(r: BigUint, s: BigUint) -> Self {
        Self { r, s }
    }

    /// DER encode as: 0x30 len 0x02 rlen r 0x02 slen s
    /// (No sighash byte; Bitcoin appends that separately.)
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let rb = der_int(&self.r)?;
        let sb = der_int(&self.s)?;

        let mut inner = Vec::with_capacity(2 + rb.len() + 2 + sb.len());
        inner.push(0x02);
        inner.push(rb.len() as u8);
        inner.extend_from_slice(&rb);

        inner.push(0x02);
        inner.push(sb.len() as u8);
        inner.extend_from_slice(&sb);

        if inner.len() > 0xff {
            return Err(Error::InvalidInput("DER signature too long"));
        }

        let mut out = Vec::with_capacity(2 + inner.len());
        out.push(0x30);
        out.push(inner.len() as u8);
        out.extend_from_slice(&inner);
        Ok(out)
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        if der.len() < 8 {
            return Err(Error::InvalidInput("DER too short"));
        }
        if der[0] != 0x30 {
            return Err(Error::InvalidInput("DER: expected 0x30"));
        }
        let total_len = der[1] as usize;
        if total_len + 2 != der.len() {
            return Err(Error::InvalidInput("DER: length mismatch"));
        }

        let mut i = 2;

        // INTEGER r
        if der[i] != 0x02 {
            return Err(Error::InvalidInput("DER: expected INTEGER for r"));
        }
        i += 1;
        let rlen = der[i] as usize;
        i += 1;
        if i + rlen > der.len() {
            return Err(Error::InvalidInput("DER: r length out of bounds"));
        }
        let r = parse_der_int(&der[i..i + rlen])?;
        i += rlen;

        // INTEGER s
        if i >= der.len() || der[i] != 0x02 {
            return Err(Error::InvalidInput("DER: expected INTEGER for s"));
        }
        i += 1;
        let slen = der[i] as usize;
        i += 1;
        if i + slen != der.len() {
            return Err(Error::InvalidInput("DER: s length mismatch"));
        }
        let s = parse_der_int(&der[i..i + slen])?;

        Ok(Signature { r, s })
    }
}

fn der_int(x: &BigUint) -> Result<Vec<u8>> {
    // Minimal big-endian bytes, no leading zeros, but if high first byte >= 0x80 prepend 0x00.
    let mut b = x.to_be_bytes_minimal();
    if b.is_empty() {
        b.push(0);
    }
    if b[0] & 0x80 != 0 {
        let mut out = Vec::with_capacity(b.len() + 1);
        out.push(0x00);
        out.extend_from_slice(&b);
        return Ok(out);
    }
    Ok(b)
}

fn parse_der_int(b: &[u8]) -> Result<BigUint> {
    if b.is_empty() {
        return Err(Error::InvalidInput("DER int empty"));
    }
    // DER allows leading 0x00 only to force positive.
    let mut bytes = b;
    if bytes.len() > 1 && bytes[0] == 0x00 {
        bytes = &bytes[1..];
    }
    Ok(BigUint::from_be_bytes(bytes))
}
