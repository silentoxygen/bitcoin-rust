//! ECDSA over secp256k1 (sign/verify) for Bitcoin-style signatures.

pub mod sign;
pub mod signature;

pub use sign::sign_digest;
pub use signature::Signature;
