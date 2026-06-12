use dilithium::dilithium::{
    generate_user_key, load_keys, save_keys, sign_friendship, verify_friendship,
};
use hex::encode;
use hex_literal::hex;
use pqcrypto_traits::sign::{PublicKey, SecretKey};

/// Demonstrates the full Dilithium post-quantum signature lifecycle:
/// key generation, signing, persistence, verification, reload, and cleanup.
///
/// # Panics
///
/// Panics if signature verification fails or if the reloaded public key
/// does not match the original, indicating a serialisation error.
fn main() {
    let (mut pubk, mut seck) = generate_user_key();
    let payload = br#"{ "from":"alice", "to":"bob", "nonce":"42" }"#;
    println!("pubk (hex): {}", encode(pubk.as_bytes()));
    println!("seck (hex): {}", encode(seck.as_bytes()));
    let sig = sign_friendship(&mut seck, payload);
    save_keys(&pubk, &seck, "example_alice").expect("save failed");
    let ok = verify_friendship(&pubk, payload, &sig);
    println!("Signature valide ? {}", ok);
    assert!(ok, "signature verification must succeed");
    let (loaded_pub, _loaded_sec) = load_keys("example_alice");
    assert!(
        pubk == loaded_pub,
        "reloaded public key must match the original"
    );
    let _ = std::fs::remove_file("example_alice.pub");
    let _ = std::fs::remove_file("example_alice.sec");
}
