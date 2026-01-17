
# bitcoin-rust — Bitcoin From Scratch in Rust

This repository is a **from‑scratch implementation of Bitcoin’s cryptographic core**, written in Rust **without using external crypto libraries**.

It follows (and goes beyond) the classic “Bitcoin from scratch” educational articles by implementing the real mathematics and encodings used by Bitcoin Core, while keeping the code readable, auditable, and pedagogical.

> **Status:** Working, end‑to‑end cryptographic pipeline  
> **Scope:** Keys → Addresses → Hashing → ECDSA signing  
> **Network:** Bitcoin Testnet (P2PKH)

---

## What This Project Demonstrates

Running the binary produces a full Bitcoin‑correct flow:

1. **Private key → Public key** (secp256k1 scalar multiplication)
2. **SEC encoding** (compressed public key format)
3. **Bitcoin address derivation** (P2PKH, Base58Check)
4. **Message hashing** (double SHA‑256)
5. **ECDSA signing** (RFC6979, low‑S normalization)
6. **DER encoding** (Bitcoin‑standard signatures)
7. **Hash sanity checks** (known test vectors)

This is the same cryptographic pipeline used by Bitcoin Core.

---

## Example Output

```text
=== btc-from-scratch sanity test ===
[1] computing pubkey = secret*G ...
[2] encoding SEC ...
Public key (SEC compressed): 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
[3] deriving address ...
Testnet address (P2PKH): mxqX27CWwZfewbg2nmNGpeRTSjo84eVTa5
[4] preparing message digest ...
Digest (sha256d): 511c3fd2de994dde6c3d5d800a821f1275c699c4b814f4a9434eb7161a0d408b
[5] signing digest ...
[6] signature computed.
Signature (DER): 30440220...
[7] SHA256 sanity ...
SHA256("") = 065e56d2e3b47e534074db6ef4793b6ac2e3027f542eec9c227cac2dc352a9db
=== done ===
```

---

## Project Structure

```text
src/
├── bitcoin/
│   ├── address.rs
│   ├── base58.rs
│   └── mod.rs
│
├── crypto/
│   ├── sha256.rs
│   ├── ripemd160.rs
│   ├── hmac_sha256.rs
│   └── mod.rs
│
├── ecdsa/
│   ├── sign.rs
│   ├── signature.rs
│   └── mod.rs
│
├── math/
│   ├── bigint.rs
│   ├── euclid.rs
│   └── mod.rs
│
├── secp256k1/
│   ├── curve.rs
│   ├── point.rs
│   ├── pubkey.rs
│   └── mod.rs
│
├── util/
│   ├── bytes.rs
│   └── mod.rs
│
├── errors.rs
├── lib.rs
└── main.rs
```

---

## Cryptographic Guarantees

- secp256k1 elliptic curve
- Deterministic ECDSA (RFC6979)
- Low‑S normalization (Bitcoin standard)
- Strict DER encoding
- Custom BigUint implementation
- No external crypto libraries

---

## Build and Run

```bash
cargo build --release
cargo run --release
```

---

