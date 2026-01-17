//! Base58 and Base58Check (Bitcoin) encoding/decoding.

use crate::crypto::sha256::sha256;
use crate::errors::{Error, Result};

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn index_of(c: u8) -> Option<u8> {
    for (i, &a) in ALPHABET.iter().enumerate() {
        if a == c {
            return Some(i as u8);
        }
    }
    None
}

/// Encode bytes into Base58 string.
pub fn base58_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // Count leading zeros.
    let mut zeros = 0usize;
    for &b in data {
        if b == 0 {
            zeros += 1;
        } else {
            break;
        }
    }

    // Base conversion: base256 -> base58.
    let mut input = data.to_vec();
    let mut encoded: Vec<u8> = Vec::new();

    while !input.is_empty() && input.iter().any(|&b| b != 0) {
        let mut remainder: u32 = 0;
        let mut new_input: Vec<u8> = Vec::with_capacity(input.len());

        for &b in &input {
            let acc = (remainder << 8) | (b as u32);
            let digit = (acc / 58) as u8;
            remainder = acc % 58;

            if !new_input.is_empty() || digit != 0 {
                new_input.push(digit);
            }
        }

        encoded.push(ALPHABET[remainder as usize]);
        input = new_input;
    }

    // Add leading '1's for each leading zero byte.
    for _ in 0..zeros {
        encoded.push(ALPHABET[0]);
    }

    encoded.reverse();

    // This should always be valid ASCII; lossless here.
    String::from_utf8_lossy(&encoded).to_string()
}

/// Decode Base58 string into raw bytes.
pub fn base58_decode(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = s.as_bytes();

    // Count leading '1's.
    let mut zeros = 0usize;
    for &c in bytes {
        if c == ALPHABET[0] {
            zeros += 1;
        } else {
            break;
        }
    }

    // Base conversion: base58 -> base256.
    let mut out: Vec<u8> = Vec::new();

    for &c in bytes {
        let val = index_of(c).ok_or(Error::InvalidInput("invalid base58 character"))? as u32;

        let mut carry = val;
        for b in out.iter_mut() {
            let t = (*b as u32) * 58 + carry;
            *b = (t & 0xff) as u8;
            carry = t >> 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    out.reverse();

    // Re-add leading zeros.
    if zeros > 0 {
        let mut pref = vec![0u8; zeros];
        pref.extend_from_slice(&out);
        out = pref;
    }

    Ok(out)
}

/// Bitcoin checksum = first 4 bytes of SHA256(SHA256(payload))
fn checksum4(payload: &[u8]) -> [u8; 4] {
    let h1 = sha256(payload);
    let h2 = sha256(&h1);
    [h2[0], h2[1], h2[2], h2[3]]
}

/// Base58Check encode: append 4-byte checksum then Base58 encode.
pub fn base58check_encode(payload: &[u8]) -> String {
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&checksum4(payload));
    base58_encode(&buf)
}

/// Base58Check decode: verify checksum and return payload (without checksum).
pub fn base58check_decode(s: &str) -> Result<Vec<u8>> {
    let raw = base58_decode(s)?;
    if raw.len() < 4 {
        return Err(Error::InvalidInput("base58check too short"));
    }
    let (payload, csum) = raw.split_at(raw.len() - 4);
    let want = checksum4(payload);

    if csum != &want[..] {
        return Err(Error::InvalidInput("base58check checksum mismatch"));
    }
    Ok(payload.to_vec())
}
