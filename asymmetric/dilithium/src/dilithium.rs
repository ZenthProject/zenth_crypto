
use pqcrypto_traits::sign::{
    DetachedSignature as TraitDetachedSignature,
    PublicKey as TraitPublicKey,
    SecretKey as TraitSecretKey,
};

use serde::{Deserialize, Serialize};
use std::fs;

use pqcrypto_mldsa::mldsa44::{
    DetachedSignature,
    PublicKey,
    SecretKey,
    detached_sign,
    keypair,
    verify_detached_signature,
};


/// Generates a fresh Dilithium2 keypair suitable for signing and verification.
///
/// Each call produces a statistically unique keypair using the underlying
/// `pqcrypto_dilithium` CSPRNG. The returned secret key must be kept confidential
/// and zeroized when no longer needed.
///
/// # Returns
///
/// A `(PublicKey, SecretKey)` tuple. The public key may be freely distributed;
/// the secret key must remain private.
pub fn generate_user_key() -> (PublicKey, SecretKey) {
    keypair()
}

/// Produces a Dilithium2 detached signature over `message` using `secret_key`.
///
/// The signature is computed deterministically from the secret key and message.
/// It can be verified independently by any party holding the corresponding public key.
///
/// # Arguments
///
/// * `secret_key` — the signer's Dilithium2 secret key.
/// * `message`    — arbitrary byte slice to sign.
///
/// # Returns
///
/// A [`DetachedSignature`] that can be transmitted alongside the original message.
pub fn sign_friendship(secret_key: &SecretKey, message: &[u8]) -> DetachedSignature {
    detached_sign(message, secret_key)
}

/// Verifies a Dilithium2 detached signature against a message and public key.
///
/// Returns `true` if the signature was produced by the holder of the secret key
/// corresponding to `public_key` over the exact same `message` bytes.
///
/// # Arguments
///
/// * `public_key` — the signer's Dilithium2 public key.
/// * `message`    — the original message that was signed.
/// * `signature`  — the detached signature to verify.
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_friendship(
    public_key: &PublicKey,
    message: &[u8],
    signature: &DetachedSignature,
) -> bool {
    verify_detached_signature(signature, message, public_key).is_ok()
}

/// Persists a Dilithium2 keypair to disk as raw byte files.
///
/// Two files are created in the current working directory:
/// `<user_id>.pub` for the public key and `<user_id>.sec` for the secret key.
/// Both files contain the raw key bytes with no additional encoding.
///
/// # Arguments
///
/// * `pub_key` — the public key to write.
/// * `sec_key` — the secret key to write.
/// * `user_id` — base name used to derive the file paths.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if either file cannot be created or written.
pub fn save_keys(pub_key: &PublicKey, sec_key: &SecretKey, user_id: &str) -> std::io::Result<()> {
    fs::write(format!("{}.pub", user_id), pub_key.as_bytes())?;
    fs::write(format!("{}.sec", user_id), sec_key.as_bytes())?;
    Ok(())
}

/// Signs a message with a Dilithium2 secret key supplied as raw bytes.
///
/// The key bytes are validated and converted into a strongly typed
/// [`SecretKey`] before signing. The returned signature is serialized as raw
/// bytes so it can be stored or transmitted independently of the message.
///
/// # Arguments
///
/// * `secret_key_bytes` — raw bytes representing a Dilithium2 secret key.
/// * `message` — arbitrary byte slice to sign.
///
/// # Returns
///
/// The raw detached signature bytes on success, or an error if the secret key
/// bytes do not represent a valid Dilithium2 secret key.
pub fn sign_with_dilithium2(secret_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let secret_key = SecretKey::from_bytes(secret_key_bytes)
        .map_err(|_| "Invalid Dilithium2 secret key format")?;
    let signature = detached_sign(message, &secret_key);
    Ok(signature.as_bytes().to_vec())
}

/// Loads a Dilithium2 keypair from disk previously saved with [`save_keys`].
///
/// Reads `<user_id>.pub` and `<user_id>.sec` and deserialises them back into
/// strongly-typed key objects.
///
/// # Arguments
///
/// * `user_id` — base name used to locate the key files on disk.
///
/// # Returns
///
/// A `(PublicKey, SecretKey)` tuple reconstructed from the stored bytes.
///
/// # Panics
///
/// Panics if either file cannot be read or if the bytes do not represent a valid
/// Dilithium2 key of the expected length.
pub fn load_keys(user_id: &str) -> (PublicKey, SecretKey) {
    let pub_bytes = fs::read(format!("{}.pub", user_id)).expect("public key file");
    let sec_bytes = fs::read(format!("{}.sec", user_id)).expect("secret key file");
    (
        <pqcrypto_mldsa::mldsa44::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(
            &pub_bytes,
        )
        .expect("valid public key bytes"),
        <pqcrypto_mldsa::mldsa44::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(
            &sec_bytes,
        )
        .expect("valid secret key bytes"),
    )
}

/// Serialisable proof bundling a friendship attestation with its Dilithium2 signature.
///
/// Produced by the signer after calling [`sign_friendship`] and transmitted to the
/// verifying party, who reconstructs the original message and calls [`verify_friendship`].
#[derive(Serialize, Deserialize)]
pub struct FriendshipProof {
    /// Identity of the party issuing the attestation.
    pub from: String,
    /// Identity of the party being attested as a friend.
    pub to: String,
    /// Random nonce preventing replay of a previous proof.
    pub nonce: String,
    /// ISO-8601 timestamp at which the proof was created.
    pub timestamp: String,
    /// Raw Dilithium2 detached signature bytes over the attested message.
    pub signature: Vec<u8>,
}


