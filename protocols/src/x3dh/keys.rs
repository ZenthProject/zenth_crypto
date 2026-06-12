//! X3DH key types: identity keys, prekeys, and ephemeral key pairs.
//!
//! Based on the Signal Protocol's X3DH specification and the libsignal implementation.
//!
//! `ZeroizeOnDrop` generates `Drop` impls that confuse rustc's liveness analysis,
//! producing false-positive `unused_assignments` warnings on fields of zeroized structs.
#![allow(unused_assignments)]

use rand::{CryptoRng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

use exchange::curve25519::{PrivateKey as X25519PrivateKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

use crate::errors::{RatchetError, Result};

/// Size of X25519 public/private keys
pub const EC_KEY_SIZE: usize = PUBLIC_KEY_LENGTH;

/// Size of XEdDSA signatures
pub const SIGNATURE_SIZE: usize = SIGNATURE_LENGTH;

/// Identity key pair (long-term)
///
/// Used for authentication and signing prekeys.
/// This key should be stored securely and backed up.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    #[zeroize(skip)]
    private_key: X25519PrivateKey,
    public_key: [u8; EC_KEY_SIZE],
}

impl IdentityKeyPair {
    /// Generate a new random identity key pair.
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let private_key = X25519PrivateKey::new(csprng);
        let public_key = private_key.derive_public_key_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    /// Create from existing private key bytes.
    pub fn from_private_key(private_key_bytes: [u8; EC_KEY_SIZE]) -> Self {
        let private_key = X25519PrivateKey::from(private_key_bytes);
        let public_key = private_key.derive_public_key_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    /// Get the private key.
    pub fn private_key(&self) -> &X25519PrivateKey {
        &self.private_key
    }

    /// Get the public key.
    pub fn public_key(&self) -> IdentityKey {
        IdentityKey::from_bytes(self.public_key)
    }

    /// Get the raw public key bytes.
    pub fn public_key_bytes(&self) -> &[u8; EC_KEY_SIZE] {
        &self.public_key
    }

    /// Get the raw private key bytes.
    pub fn private_key_bytes(&self) -> [u8; EC_KEY_SIZE] {
        self.private_key.private_key_bytes()
    }

    /// Sign a message using XEdDSA.
    pub fn sign<R: CryptoRng + Rng>(&self, csprng: &mut R, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        self.private_key.calculate_signature(csprng, &[message])
    }

    /// Perform DH key agreement.
    pub fn calculate_agreement(&self, their_public: &[u8; EC_KEY_SIZE]) -> [u8; EC_KEY_SIZE] {
        self.private_key.calculate_agreement(their_public)
    }
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public_key", &hex::encode(self.public_key))
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Identity key (public only)
///
/// Used to identify a user. Should be verified out-of-band (fingerprint).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentityKey {
    public_key: [u8; EC_KEY_SIZE],
}

impl IdentityKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; EC_KEY_SIZE]) -> Self {
        Self { public_key: bytes }
    }

    /// Get the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8; EC_KEY_SIZE] {
        &self.public_key
    }

    /// Verify a signature made by this identity key.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8; SIGNATURE_SIZE]) -> bool {
        X25519PrivateKey::verify_signature(&self.public_key, &[message], signature)
    }

    /// Serialize to bytes (with a `0x05` Curve25519 type-prefix for compatibility).
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + EC_KEY_SIZE);
        result.push(0x05);
        result.extend_from_slice(&self.public_key);
        result
    }

    /// Deserialize from bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == EC_KEY_SIZE {
            let mut public_key = [0u8; EC_KEY_SIZE];
            public_key.copy_from_slice(bytes);
            return Ok(Self { public_key });
        }
        if bytes.len() == EC_KEY_SIZE + 1 && bytes[0] == 0x05 {
            let mut public_key = [0u8; EC_KEY_SIZE];
            public_key.copy_from_slice(&bytes[1..]);
            return Ok(Self { public_key });
        }
        Err(RatchetError::InvalidKeyLength {
            expected: EC_KEY_SIZE,
            got: bytes.len(),
        })
    }
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityKey({})", hex::encode(&self.public_key[..8]))
    }
}

impl std::fmt::Display for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.public_key[..8]))
    }
}

/// Key pair for EC operations (signed prekey, one-time prekey, base key).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub private_key: X25519PrivateKey,
    pub public_key: [u8; EC_KEY_SIZE],
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let private_key = X25519PrivateKey::new(csprng);
        let public_key = private_key.derive_public_key_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    /// Create from existing private key bytes.
    pub fn from_private_key(private_key_bytes: [u8; EC_KEY_SIZE]) -> Self {
        let private_key = X25519PrivateKey::from(private_key_bytes);
        let public_key = private_key.derive_public_key_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    /// Perform DH key agreement.
    pub fn calculate_agreement(&self, their_public: &[u8; EC_KEY_SIZE]) -> [u8; EC_KEY_SIZE] {
        self.private_key.calculate_agreement(their_public)
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &hex::encode(&self.public_key[..8]))
            .finish()
    }
}

/// Signed pre-key (medium-term)
///
/// Published to server, signed by identity key.
/// Rotated periodically (e.g., weekly).
#[derive(Clone)]
pub struct SignedPreKey {
    pub id: u32,
    pub key_pair: KeyPair,
    pub signature: [u8; SIGNATURE_SIZE],
}

impl SignedPreKey {
    /// Generate a new signed pre-key.
    pub fn generate<R: CryptoRng + Rng>(
        id: u32,
        identity_key: &IdentityKeyPair,
        csprng: &mut R,
    ) -> Self {
        let key_pair = KeyPair::generate(csprng);
        let signature = identity_key.sign(csprng, &key_pair.public_key);
        Self {
            id,
            key_pair,
            signature,
        }
    }

    /// Verify the signature against an identity key.
    pub fn verify(&self, identity_key: &IdentityKey) -> bool {
        identity_key.verify_signature(&self.key_pair.public_key, &self.signature)
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> &[u8; EC_KEY_SIZE] {
        &self.key_pair.public_key
    }
}

impl std::fmt::Debug for SignedPreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedPreKey")
            .field("id", &self.id)
            .field("public_key", &hex::encode(&self.key_pair.public_key[..8]))
            .finish()
    }
}

/// One-time pre-key (ephemeral)
///
/// Published to server, used once then deleted.
/// Provides forward secrecy for initial message.
#[derive(Clone)]
pub struct OneTimePreKey {
    pub id: u32,
    pub key_pair: KeyPair,
}

impl OneTimePreKey {
    /// Generate a new one-time pre-key.
    pub fn generate<R: CryptoRng + Rng>(id: u32, csprng: &mut R) -> Self {
        Self {
            id,
            key_pair: KeyPair::generate(csprng),
        }
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> &[u8; EC_KEY_SIZE] {
        &self.key_pair.public_key
    }
}

impl std::fmt::Debug for OneTimePreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimePreKey")
            .field("id", &self.id)
            .field("public_key", &hex::encode(&self.key_pair.public_key[..8]))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_identity_key_generation() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);

        assert_eq!(identity.public_key_bytes().len(), EC_KEY_SIZE);
    }

    #[test]
    fn test_identity_key_signature() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);

        let message = b"test message";
        let signature = identity.sign(&mut rng, message);

        assert!(identity.public_key().verify_signature(message, &signature));
    }

    #[test]
    fn test_identity_key_signature_invalid() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);

        let message = b"test message";
        let signature = identity.sign(&mut rng, message);

        let wrong_message = b"wrong message";
        assert!(!identity
            .public_key()
            .verify_signature(wrong_message, &signature));
    }

    #[test]
    fn test_signed_prekey() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);
        let signed_prekey = SignedPreKey::generate(1, &identity, &mut rng);

        assert!(signed_prekey.verify(&identity.public_key()));
    }

    #[test]
    fn test_key_agreement() {
        let mut rng = OsRng;
        let alice = KeyPair::generate(&mut rng);
        let bob = KeyPair::generate(&mut rng);

        let alice_shared = alice.calculate_agreement(&bob.public_key);
        let bob_shared = bob.calculate_agreement(&alice.public_key);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_identity_key_serialization() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);

        let serialized = identity.public_key().serialize();
        let deserialized = IdentityKey::deserialize(&serialized).unwrap();

        assert_eq!(identity.public_key().as_bytes(), deserialized.as_bytes());
    }
}
