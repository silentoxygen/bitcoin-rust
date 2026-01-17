use crate::errors::{Error, Result};

/// Convert a u32 to little-endian bytes.
#[inline]
pub fn u32_le(n: u32) -> [u8; 4] {
    n.to_le_bytes()
}

/// Convert a u64 to little-endian bytes.
#[inline]
pub fn u64_le(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

/// Read a u32 from little-endian bytes.
#[inline]
pub fn read_u32_le(b: &[u8]) -> Result<u32> {
    if b.len() != 4 {
        return Err(Error::InvalidInput("u32 requires 4 bytes"));
    }
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

/// Read a u64 from little-endian bytes.
#[inline]
pub fn read_u64_le(b: &[u8]) -> Result<u64> {
    if b.len() != 8 {
        return Err(Error::InvalidInput("u64 requires 8 bytes"));
    }
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}

/// Convert bytes to lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";

    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

/// Convert hex string to bytes.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);

    if s.len() % 2 != 0 {
        return Err(Error::InvalidInput("hex string must have even length"));
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<_> = s.as_bytes().to_vec();

    for i in (0..chars.len()).step_by(2) {
        let hi = from_hex_digit(chars[i])?;
        let lo = from_hex_digit(chars[i + 1])?;
        out.push((hi << 4) | lo);
    }

    Ok(out)
}

#[inline]
fn from_hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::InvalidInput("invalid hex digit")),
    }
}

/// Concatenate multiple byte slices into a single Vec.
pub fn concat_bytes(chunks: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = chunks.iter().map(|c| c.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for c in chunks {
        out.extend_from_slice(c);
    }
    out
}

/// Reverse bytes (used heavily in Bitcoin for endianness).
#[inline]
pub fn reverse_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = b.to_vec();
    out.reverse();
    out
}
