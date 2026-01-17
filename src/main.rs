use btc_from_scratch::{
    bitcoin::address::{p2pkh_address_from_pubkey, Network},
    crypto::sha256::sha256,
    ecdsa::sign::sign_digest,
    math::BigUint,
    secp256k1::curve::secp256k1_generator,
    secp256k1::point::Point,
    secp256k1::pubkey::PublicKey,
};

fn main() {
    println!("=== btc-from-scratch sanity test ===");

    let secret = BigUint::from_u64(1);

    println!("[1] computing pubkey = secret*G ...");
    let (gx, gy) = secp256k1_generator();
    let g = Point::new(gx, gy);
    let pub_point = g.mul_scalar(secret.clone()).expect("scalar mul");
    let pubkey = PublicKey::from_point(pub_point);

    println!("[2] encoding SEC ...");
    let sec = pubkey.encode_sec(true).expect("encode_sec");
    println!("Public key (SEC compressed): {}", hex(&sec));

    println!("[3] deriving address ...");
    let addr = p2pkh_address_from_pubkey(&pubkey, true, Network::Testnet).expect("address");
    println!("Testnet address (P2PKH): {}", addr);

    println!("[4] preparing message digest ...");
    let msg = b"hello bitcoin";
    let digest = sha256(&sha256(msg));
    println!("Digest (sha256d): {}", hex(&digest));

    println!("[5] signing digest ...");
    let sig = sign_digest(&secret, &digest).expect("sign_digest");
    println!("[6] signature computed.");

    let der = sig.to_der().expect("to_der");
    println!("Signature (DER): {}", hex(&der));
    println!("r (hex): {}", hex(&sig.r.to_be_bytes_fixed(32)));
    println!("s (hex): {}", hex(&sig.s.to_be_bytes_fixed(32)));

    println!("[7] SHA256 sanity ...");
    let empty = sha256(b"");
    println!("SHA256(\"\") = {}", hex(&empty));

    println!("=== done ===");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
