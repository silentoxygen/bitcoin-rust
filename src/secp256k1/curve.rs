use crate::math::BigUint;
use crate::util::bytes::hex_to_bytes;

pub fn secp256k1_prime_p() -> BigUint {
    BigUint::from_be_bytes(
        &hex_to_bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
            .expect("valid hex"),
    )
}

pub fn secp256k1_a() -> BigUint {
    BigUint::zero()
}

pub fn secp256k1_b() -> BigUint {
    BigUint::from_u64(7)
}

pub fn secp256k1_order_n() -> BigUint {
    BigUint::from_be_bytes(
        &hex_to_bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            .expect("valid hex"),
    )
}

pub fn secp256k1_generator() -> (BigUint, BigUint) {
    let x = BigUint::from_be_bytes(
        &hex_to_bytes("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
            .expect("valid hex"),
    );

    let y = BigUint::from_be_bytes(
        &hex_to_bytes("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
            .expect("valid hex"),
    );

    (x, y)
}
