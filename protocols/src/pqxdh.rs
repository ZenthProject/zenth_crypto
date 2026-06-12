//!
//! PQXDH - Post-Quantum Extended Triple Diffie-Hellman
//!
//! Combines X3DH with Kyber KEM for post-quantum security.
//! Uses rand 0.8 for curve25519 operations.
//! KEM operations use internal OsRng to avoid version conflicts.
//!

use rand::rngs::OsRng as OsRng08;

use crate::errors::{RatchetError, Result};
use crate::keys::{ChainKey, RootKey};
use crate::x3dh::{
    x3dh_alice, x3dh_bob, AliceParameters, BobParameters, IdentityKeyPair, KeyPair, OneTimePreKey,
    PreKeyBundle, SignedPreKey, EC_KEY_SIZE,
};

use kem::{KeyPair as KemKeyPair, KeyType, PublicKey as KemPublicKey, SecretKey as KemSecretKey};

use hkdf::Hkdf;
use sha2::Sha256;

/// Kyber key type to use (Kyber1024 for highest security)
pub const KYBER_TYPE: KeyType = KeyType::Kyber1024;

/// PQXDH info label for key derivation
const PQXDH_INFO: &[u8] = b"PQXDH";

/// Signed Kyber pre-key for PQXDH
pub struct SignedKyberPreKey {
    pub id: u32,
    pub public_key: KemPublicKey,
    pub secret_key: KemSecretKey,
    pub signature: [u8; 64], // XEdDSA signature
}

impl SignedKyberPreKey {
    /// Generate a new signed Kyber pre-key
    pub fn generate(id: u32, identity_key: &IdentityKeyPair) -> Self {
        let mut rng08 = OsRng08;
        let keypair = KemKeyPair::generate_with_os_rng(KYBER_TYPE);
        let signature = identity_key.sign(&mut rng08, &keypair.public_key.serialize());

        Self {
            id,
            public_key: keypair.public_key,
            secret_key: keypair.secret_key,
            signature,
        }
    }

    /// Verify the signature
    pub fn verify(&self, identity_key: &crate::x3dh::IdentityKey) -> bool {
        identity_key.verify_signature(&self.public_key.serialize(), &self.signature)
    }
}

/// Extended PreKeyBundle with Kyber key for PQXDH
#[derive(Clone)]
pub struct PQPreKeyBundle {
    /// Classic X3DH bundle
    pub x3dh_bundle: PreKeyBundle,
    /// Kyber pre-key ID
    pub kyber_pre_key_id: u32,
    /// Kyber pre-key public key
    pub kyber_pre_key: Vec<u8>,
    /// Kyber pre-key signature
    pub kyber_pre_key_signature: [u8; 64],
}

impl PQPreKeyBundle {
    /// Create a new PQXDH bundle
    pub fn new(x3dh_bundle: PreKeyBundle, kyber_prekey: &SignedKyberPreKey) -> Self {
        Self {
            x3dh_bundle,
            kyber_pre_key_id: kyber_prekey.id,
            kyber_pre_key: kyber_prekey.public_key.serialize(),
            kyber_pre_key_signature: kyber_prekey.signature,
        }
    }

    /// Verify all signatures in the bundle
    pub fn verify(&self) -> Result<()> {
        self.x3dh_bundle.verify()?;

        if !self
            .x3dh_bundle
            .identity_key
            .verify_signature(&self.kyber_pre_key, &self.kyber_pre_key_signature)
        {
            return Err(RatchetError::InvalidSignature);
        }

        Ok(())
    }
}

/// Result of PQXDH key agreement from Alice's side
#[derive(Debug)]
pub struct AlicePQXDHResult {
    /// Root key for Double Ratchet
    pub root_key: RootKey,
    /// Initial chain key for sending
    pub chain_key: ChainKey,
    /// Alice's ephemeral base key public (to send to Bob)
    pub ephemeral_public: [u8; EC_KEY_SIZE],
    /// Kyber ciphertext (to send to Bob)
    pub kyber_ciphertext: Vec<u8>,
    /// Which one-time pre-key was used (if any)
    pub one_time_pre_key_id: Option<u32>,
}

/// Result of PQXDH key agreement from Bob's side
#[derive(Debug)]
pub struct BobPQXDHResult {
    /// Root key for Double Ratchet
    pub root_key: RootKey,
    /// Initial chain key for receiving
    pub chain_key: ChainKey,
}

/// Perform PQXDH key agreement as Alice (initiator)
pub fn pqxdh_alice(
    our_identity_key: &IdentityKeyPair,
    their_bundle: &PQPreKeyBundle,
) -> Result<AlicePQXDHResult> {
    let mut rng08 = OsRng08;

    their_bundle.verify()?;

    let base_key = KeyPair::generate(&mut rng08);

    let x3dh_params = AliceParameters {
        our_identity_key,
        our_base_key: &base_key,
        their_bundle: &their_bundle.x3dh_bundle,
    };

    let x3dh_result = x3dh_alice(&x3dh_params, &mut rng08)?;

    let kyber_pk = KemPublicKey::deserialize(&their_bundle.kyber_pre_key).map_err(|_| {
        RatchetError::InvalidKeyLength {
            expected: 0,
            got: 0,
        }
    })?;

    let (kyber_ss, kyber_ct) =
        kyber_pk
            .encapsulate_with_os_rng()
            .map_err(|_| RatchetError::InvalidKeyLength {
                expected: 0,
                got: 0,
            })?;

    let (root_key, chain_key) = derive_pqxdh_keys(
        x3dh_result.root_key.key(),
        x3dh_result.chain_key.key(),
        &kyber_ss,
    );

    Ok(AlicePQXDHResult {
        root_key,
        chain_key,
        ephemeral_public: x3dh_result.ephemeral_public,
        kyber_ciphertext: kyber_ct.to_vec(),
        one_time_pre_key_id: x3dh_result.one_time_pre_key_id,
    })
}

/// Parameters needed by Bob to complete PQXDH
pub struct BobPQXDHParameters<'a> {
    /// Bob's identity key pair
    pub our_identity_key: &'a IdentityKeyPair,
    /// Bob's signed pre-key pair
    pub our_signed_pre_key: &'a SignedPreKey,
    /// Bob's one-time pre-key pair (if Alice used one)
    pub our_one_time_pre_key: Option<&'a OneTimePreKey>,
    /// Bob's Kyber pre-key
    pub our_kyber_pre_key: &'a SignedKyberPreKey,
    /// Alice's identity key
    pub their_identity_key: &'a [u8; EC_KEY_SIZE],
    /// Alice's ephemeral base key
    pub their_base_key: &'a [u8; EC_KEY_SIZE],
    /// Alice's Kyber ciphertext
    pub their_kyber_ciphertext: &'a [u8],
}

/// Perform PQXDH key agreement as Bob (responder)
pub fn pqxdh_bob(params: &BobPQXDHParameters) -> Result<BobPQXDHResult> {
    let x3dh_params = BobParameters {
        our_identity_key: params.our_identity_key,
        our_signed_pre_key: params.our_signed_pre_key,
        our_one_time_pre_key: params.our_one_time_pre_key,
        their_identity_key: params.their_identity_key,
        their_base_key: params.their_base_key,
    };

    let x3dh_result = x3dh_bob(&x3dh_params)?;

    let kyber_ss = params
        .our_kyber_pre_key
        .secret_key
        .decapsulate(params.their_kyber_ciphertext)
        .map_err(|_| RatchetError::DecryptionFailed("Kyber decapsulation failed".into()))?;

    let (root_key, chain_key) = derive_pqxdh_keys(
        x3dh_result.root_key.key(),
        x3dh_result.chain_key.key(),
        &kyber_ss,
    );

    Ok(BobPQXDHResult {
        root_key,
        chain_key,
    })
}

/// Derive PQXDH session keys by combining X3DH and Kyber shared secrets
fn derive_pqxdh_keys(
    x3dh_root: &[u8; 32],
    x3dh_chain: &[u8; 32],
    kyber_ss: &[u8],
) -> (RootKey, ChainKey) {
    let mut ikm = Vec::with_capacity(32 + 32 + kyber_ss.len());
    ikm.extend_from_slice(x3dh_root);
    ikm.extend_from_slice(x3dh_chain);
    ikm.extend_from_slice(kyber_ss);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 64];
    hk.expand(PQXDH_INFO, &mut okm)
        .expect("valid output length");

    let mut root_bytes = [0u8; 32];
    let mut chain_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&okm[..32]);
    chain_bytes.copy_from_slice(&okm[32..]);

    (RootKey::new(root_bytes), ChainKey::new(chain_bytes, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqxdh_agreement() {
        let mut rng = OsRng08;

        // Bob's keys
        let bob_identity = IdentityKeyPair::generate(&mut rng);
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity, &mut rng);
        let bob_one_time_prekey = OneTimePreKey::generate(1, &mut rng);
        let bob_kyber_prekey = SignedKyberPreKey::generate(1, &bob_identity);

        // Create Bob's X3DH bundle
        let x3dh_bundle = PreKeyBundle::new(
            12345,
            1,
            bob_identity.public_key(),
            bob_signed_prekey.id,
            *bob_signed_prekey.public_key(),
            bob_signed_prekey.signature,
            Some(bob_one_time_prekey.id),
            Some(*bob_one_time_prekey.public_key()),
        );

        // Create PQXDH bundle
        let pq_bundle = PQPreKeyBundle::new(x3dh_bundle, &bob_kyber_prekey);

        // Alice initiates PQXDH
        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let alice_result = pqxdh_alice(&alice_identity, &pq_bundle).unwrap();

        // Bob responds
        let bob_params = BobPQXDHParameters {
            our_identity_key: &bob_identity,
            our_signed_pre_key: &bob_signed_prekey,
            our_one_time_pre_key: Some(&bob_one_time_prekey),
            our_kyber_pre_key: &bob_kyber_prekey,
            their_identity_key: alice_identity.public_key_bytes(),
            their_base_key: &alice_result.ephemeral_public,
            their_kyber_ciphertext: &alice_result.kyber_ciphertext,
        };

        let bob_result = pqxdh_bob(&bob_params).unwrap();

        // Both should derive the same keys
        assert_eq!(alice_result.root_key.key(), bob_result.root_key.key());
        assert_eq!(alice_result.chain_key.key(), bob_result.chain_key.key());
    }

    #[test]
    fn test_signed_kyber_prekey() {
        let mut rng = OsRng08;
        let identity = IdentityKeyPair::generate(&mut rng);
        let kyber_prekey = SignedKyberPreKey::generate(1, &identity);

        // Verify signature
        assert!(kyber_prekey.verify(&identity.public_key()));

        // Wrong identity should fail
        let wrong_identity = IdentityKeyPair::generate(&mut rng);
        assert!(!kyber_prekey.verify(&wrong_identity.public_key()));
    }
}
