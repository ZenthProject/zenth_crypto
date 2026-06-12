use pqcrypto_dilithium::dilithium2::{
    DetachedSignature, PublicKey, SecretKey, detached_sign, keypair, verify_detached_signature,
};
use pqcrypto_traits::sign::DetachedSignature as _;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct FriendshipProof {
    from: String,
    to: String,
    timestamp: String,
    signature: Vec<u8>,
}

/// Demonstrates peer-to-peer friendship attestation using a Dilithium2 detached signature.
///
/// Alice generates a keypair, signs a friendship message addressed to Bob, and packages
/// the signature alongside the attestation metadata into a [`FriendshipProof`]. Bob (or
/// any third party holding Alice's public key) can then verify the proof independently.
///
/// # Panics
///
/// Panics if signature verification fails, indicating key or message corruption.
fn main() {
    let (alice_pub, alice_sec): (PublicKey, SecretKey) = keypair();

    let message = b"Alice reconnait Bob comme ami - 2025-11-04T01:58:00Z";

    let sig: DetachedSignature = detached_sign(message, &alice_sec);

    let proof = FriendshipProof {
        from: "Alice".to_string(),
        to: "Bob".to_string(),
        timestamp: "2025-11-04T01:58:00Z".to_string(),
        signature: sig.as_bytes().to_vec(),
    };

    let ok = verify_detached_signature(&sig, message, &alice_pub).is_ok();
    println!("Preuve vérifiée ? {}", ok);
}
