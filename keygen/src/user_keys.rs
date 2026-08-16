use kem::{KeyPair,KeyType};
use asymmetric::dilithium::dilithium::generate_user_key;
use rand08::rngs::OsRng as OsRng08;
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};
use pqcrypto_dilithium::dilithium2::{PublicKey, SecretKey};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};

/// Generate a X25519 keypair for ECDH key exchange
///
/// Returns a tuple of (secret_key, public_key) where:
/// - secret_key: StaticSecret (32 bytes)
/// - public_key: X25519PublicKey (32 bytes)
pub fn generate_x25519_keypair() -> (StaticSecret, X25519PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng08);
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

/// Generate a Kyber1024 keypair for post-quantum KEM
///
/// Returns a tuple of (public_key_bytes, secret_key_bytes) where:
/// - public_key_bytes: Vec<u8> (1568 bytes for Kyber1024)
/// - secret_key_bytes: Vec<u8> (3168 bytes for Kyber1024)
pub fn generate_kyber_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut rng = rand::rng();
    let kyber_keypair = KeyPair::generate(KeyType::Kyber1024, &mut rng);
    let public_bytes = kyber_keypair.public_key.serialize();
    let secret_bytes = kyber_keypair.secret_key.serialize();
    Ok((public_bytes, secret_bytes))
}

pub fn generate_user_crypto_keys() -> Result<(
    PublicKey,
    SecretKey,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>
), String> {
    let (dilithium_public, dilithium_secret) = generate_user_key();
    let identity_key_dilithium = dilithium_public.as_bytes().to_vec();
    let identity_key_dilithium_secret = dilithium_secret.as_bytes().to_vec();
    let mut rng = rand::rng();
    let kyber_keypair = KeyPair::generate(KeyType::Kyber1024, &mut rng);
    let kyber_public_bytes = kyber_keypair.public_key.serialize();
    let kyber_secret_bytes = kyber_keypair.secret_key.serialize();

    Ok((
        dilithium_public,
        dilithium_secret,
        identity_key_dilithium,
        identity_key_dilithium_secret,
        kyber_public_bytes,
        kyber_secret_bytes,
    ))
}
