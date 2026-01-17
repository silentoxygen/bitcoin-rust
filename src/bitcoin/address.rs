//! Address helpers (legacy P2PKH only).

use crate::bitcoin::base58::base58check_encode;
use crate::errors::{Error, Result};
use crate::secp256k1::pubkey::PublicKey;

pub const VERSION_P2PKH_MAINNET: u8 = 0x00;
pub const VERSION_P2PKH_TESTNET: u8 = 0x6f;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// Build a Base58Check P2PKH address string from a 20-byte hash160.
pub fn p2pkh_from_hash160(hash160: &[u8], network: Network) -> Result<String> {
    if hash160.len() != 20 {
        return Err(Error::InvalidInput("hash160 must be 20 bytes"));
    }
    let version = match network {
        Network::Mainnet => VERSION_P2PKH_MAINNET,
        Network::Testnet => VERSION_P2PKH_TESTNET,
    };

    let mut payload = Vec::with_capacity(21);
    payload.push(version);
    payload.extend_from_slice(hash160);

    Ok(base58check_encode(&payload))
}

/// Convenience: derive hash160(pubkey SEC) then encode P2PKH.
pub fn p2pkh_address_from_pubkey(
    pubkey: &PublicKey,
    compressed: bool,
    network: Network,
) -> Result<String> {
    let h160 = pubkey.hash160(compressed)?;
    p2pkh_from_hash160(&h160, network)
}
