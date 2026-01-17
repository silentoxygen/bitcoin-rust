// Minimal RIPEMD-160 implementation (std-only), adapted from reference-style code.

use crate::errors::{Error, Result};

fn rol(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

fn k(j: usize) -> u32 {
    match j {
        0..=15 => 0x00000000,
        16..=31 => 0x5a827999,
        32..=47 => 0x6ed9eba1,
        48..=63 => 0x8f1bbcdc,
        _ => 0xa953fd4e,
    }
}

fn kk(j: usize) -> u32 {
    match j {
        0..=15 => 0x50a28be6,
        16..=31 => 0x5c4dd124,
        32..=47 => 0x6d703ef3,
        48..=63 => 0x7a6d76e9,
        _ => 0x00000000,
    }
}

const R: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

const RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

const S: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

const SS: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut h0 = 0x67452301u32;
    let mut h1 = 0xefcdab89u32;
    let mut h2 = 0x98badcfeu32;
    let mut h3 = 0x10325476u32;
    let mut h4 = 0xc3d2e1f0u32;

    let mut msg = data.to_vec();
    let bit_len = (msg.len() as u64) * 8;

    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            let j = i * 4;
            x[i] = u32::from_le_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }

        let (mut al, mut bl, mut cl, mut dl, mut el) = (h0, h1, h2, h3, h4);
        let (mut ar, mut br, mut cr, mut dr, mut er) = (h0, h1, h2, h3, h4);

        for j in 0..80 {
            let t = rol(
                al.wrapping_add(f(j, bl, cl, dl))
                    .wrapping_add(x[R[j]])
                    .wrapping_add(k(j)),
                S[j],
            )
            .wrapping_add(el);
            al = el;
            el = dl;
            dl = rol(cl, 10);
            cl = bl;
            bl = t;

            let tt = rol(
                ar.wrapping_add(f(79 - j, br, cr, dr))
                    .wrapping_add(x[RR[j]])
                    .wrapping_add(kk(j)),
                SS[j],
            )
            .wrapping_add(er);
            ar = er;
            er = dr;
            dr = rol(cr, 10);
            cr = br;
            br = tt;
        }

        let t = h1.wrapping_add(cl).wrapping_add(dr);
        h1 = h2.wrapping_add(dl).wrapping_add(er);
        h2 = h3.wrapping_add(el).wrapping_add(ar);
        h3 = h4.wrapping_add(al).wrapping_add(br);
        h4 = h0.wrapping_add(bl).wrapping_add(cr);
        h0 = t;
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_le_bytes());
    out[4..8].copy_from_slice(&h1.to_le_bytes());
    out[8..12].copy_from_slice(&h2.to_le_bytes());
    out[12..16].copy_from_slice(&h3.to_le_bytes());
    out[16..20].copy_from_slice(&h4.to_le_bytes());
    out
}

pub fn ripemd160_selftest() -> Result<()> {
    let h = ripemd160(b"hello this is a test");
    let expect = "f51960af7dd4813a587ab26388ddab3b28d1f7b4";
    if crate::util::bytes::bytes_to_hex(&h) != expect {
        return Err(Error::Msg("ripemd160 selftest failed"));
    }
    Ok(())
}
