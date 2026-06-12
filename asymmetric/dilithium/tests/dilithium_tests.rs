use dilithium::dilithium::{
    generate_user_key, load_keys, save_keys, sign_friendship, verify_friendship,
};

#[test]
fn test_lms() {
    let (alice_pub, alice_sec) = generate_user_key();
    let payload =
        br#"{ "from": "alice", "to": "bob", "nonce": "123", "timestamp": "2025-11-02T12:00:00Z" }"#;
    let sig = sign_friendship(&alice_sec, payload);
    let ok = verify_friendship(&alice_pub, payload, &sig);
    println!("Signature valide ? {}", ok);
    assert!(ok);
}

#[test]
fn test_signature_invalid_payload() {
    let (alice_pub, alice_sec) = generate_user_key();
    let payload = br#"{ "from": "alice", "to": "bob", "nonce": "123" }"#;
    let sig = sign_friendship(&alice_sec, payload);
    let tampered_payload = br#"{ "from": "alice", "to": "bob", "nonce": "999" }"#;
    let ok = verify_friendship(&alice_pub, tampered_payload, &sig);
    assert!(!ok);
}

#[test]
fn test_signature_with_different_key() {
    let (_, alice_sec) = generate_user_key();
    let (bob_pub, _) = generate_user_key();
    let payload = br#"{ "from": "alice", "to": "bob", "nonce": "123" }"#;
    let sig = sign_friendship(&alice_sec, payload);
    let ok = verify_friendship(&bob_pub, payload, &sig);
    assert!(!ok);
}

#[test]
fn test_save_and_load_keys() {
    let (alice_pub, alice_sec) = generate_user_key();

    save_keys(&alice_pub, &alice_sec, "test_alice").unwrap();
    let (loaded_pub, loaded_sec) = load_keys("test_alice");

    assert!(
        alice_pub == loaded_pub,
        "alice_pub and loaded_pub are not equal"
    );
    assert!(alice_sec == loaded_sec);

    std::fs::remove_file("test_alice.pub").unwrap();
    std::fs::remove_file("test_alice.sec").unwrap();
}
