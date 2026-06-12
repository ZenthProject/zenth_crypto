//! X3DH key agreement protocol implementation.
//!
//! Based on the Signal Protocol's X3DH specification:
//! <https://signal.org/docs/specifications/x3dh/>

use hkdf::Hkdf;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use zeroize::Zeroize;

use kdf::derive_arrays;

use crate::errors::Result;
use crate::keys::{ChainKey, RootKey};

use super::bundle::PreKeyBundle;
use super::keys::{IdentityKeyPair, KeyPair, OneTimePreKey, SignedPreKey, EC_KEY_SIZE};

/// HKDF info label for X3DH key derivation
const X3DH_INFO: &[u8] = b"WhisperText";

/// Discontinuity bytes (prepended to prevent confusion between protocol versions)
const DISCONTINUITY: [u8; 32] = [0xFF; 32];

/// Result of X3DH key agreement from Alice's side.
#[derive(Debug)]
pub struct AliceX3DHResult {
    /// Root key for Double Ratchet
    pub root_key: RootKey,
    /// Initial chain key for sending
    pub chain_key: ChainKey,
    /// Alice's ephemeral base key public (to send to Bob)
    pub ephemeral_public: [u8; EC_KEY_SIZE],
    /// Which one-time pre-key was used (if any)
    pub one_time_pre_key_id: Option<u32>,
}

/// Result of X3DH key agreement from Bob's side.
#[derive(Debug)]
pub struct BobX3DHResult {
    /// Root key for Double Ratchet
    pub root_key: RootKey,
    /// Initial chain key for receiving
    pub chain_key: ChainKey,
}

/// Parameters needed by Alice to initiate X3DH.
pub struct AliceParameters<'a> {
    /// Alice's identity key pair
    pub our_identity_key: &'a IdentityKeyPair,
    /// Alice's ephemeral base key pair (generated for this session)
    pub our_base_key: &'a KeyPair,
    /// Bob's pre-key bundle (fetched from server)
    pub their_bundle: &'a PreKeyBundle,
}

/// Parameters needed by Bob to complete X3DH.
pub struct BobParameters<'a> {
    /// Bob's identity key pair
    pub our_identity_key: &'a IdentityKeyPair,
    /// Bob's signed pre-key pair
    pub our_signed_pre_key: &'a SignedPreKey,
    /// Bob's one-time pre-key pair (if Alice used one)
    pub our_one_time_pre_key: Option<&'a OneTimePreKey>,
    /// Alice's identity key
    pub their_identity_key: &'a [u8; EC_KEY_SIZE],
    /// Alice's ephemeral base key
    pub their_base_key: &'a [u8; EC_KEY_SIZE],
}

/// Perform X3DH key agreement as Alice (initiator).
///
/// # Arguments
/// * `params` - Alice's parameters including her keys and Bob's bundle
/// * `_csprng` - Cryptographically secure RNG (unused in classic X3DH, but kept for API consistency)
///
/// # Returns
/// The X3DH result containing root key, chain key, and values to send to Bob.
pub fn x3dh_alice<R: CryptoRng + Rng>(
    params: &AliceParameters,
    _csprng: &mut R,
) -> Result<AliceX3DHResult> {
    params.their_bundle.verify()?;

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&DISCONTINUITY);

    let dh1 = params
        .our_identity_key
        .calculate_agreement(&params.their_bundle.signed_pre_key);
    secrets.extend_from_slice(&dh1);

    let dh2 = params
        .our_base_key
        .calculate_agreement(params.their_bundle.identity_key.as_bytes());
    secrets.extend_from_slice(&dh2);

    let dh3 = params
        .our_base_key
        .calculate_agreement(&params.their_bundle.signed_pre_key);
    secrets.extend_from_slice(&dh3);

    let one_time_pre_key_id = if let Some(opk) = &params.their_bundle.one_time_pre_key {
        let dh4 = params.our_base_key.calculate_agreement(opk);
        secrets.extend_from_slice(&dh4);
        params.their_bundle.one_time_pre_key_id
    } else {
        None
    };

    let (root_key, chain_key) = derive_session_keys(&secrets, X3DH_INFO);

    secrets.zeroize();

    Ok(AliceX3DHResult {
        root_key,
        chain_key,
        ephemeral_public: params.our_base_key.public_key,
        one_time_pre_key_id,
    })
}

/// Perform X3DH key agreement as Bob (responder).
///
/// # Arguments
/// * `params` - Bob's parameters including his keys and Alice's message
///
/// # Returns
/// The X3DH result containing root key and chain key.
pub fn x3dh_bob(params: &BobParameters) -> Result<BobX3DHResult> {
    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&DISCONTINUITY);

    let dh1 = params
        .our_signed_pre_key
        .key_pair
        .calculate_agreement(params.their_identity_key);
    secrets.extend_from_slice(&dh1);

    let dh2 = params
        .our_identity_key
        .calculate_agreement(params.their_base_key);
    secrets.extend_from_slice(&dh2);

    let dh3 = params
        .our_signed_pre_key
        .key_pair
        .calculate_agreement(params.their_base_key);
    secrets.extend_from_slice(&dh3);

    if let Some(opk) = params.our_one_time_pre_key {
        let dh4 = opk.key_pair.calculate_agreement(params.their_base_key);
        secrets.extend_from_slice(&dh4);
    }

    let (root_key, chain_key) = derive_session_keys(&secrets, X3DH_INFO);

    secrets.zeroize();

    Ok(BobX3DHResult {
        root_key,
        chain_key,
    })
}

/// Derive session keys from concatenated DH outputs using HKDF.
fn derive_session_keys(secrets: &[u8], info: &[u8]) -> (RootKey, ChainKey) {
    let (root_key_bytes, chain_key_bytes, []): ([u8; 32], [u8; 32], [u8; 0]) =
        derive_arrays(|bytes| {
            Hkdf::<Sha256>::new(None, secrets)
                .expand(info, bytes)
                .expect("valid output length for session keys");
        });

    (
        RootKey::new(root_key_bytes),
        ChainKey::new(chain_key_bytes, 0),
    )
}

/// Simplified X3DH for classic mode.
///
/// This is a convenience function that generates the base key internally.
pub fn x3dh_initiate<R: CryptoRng + Rng>(
    our_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
    csprng: &mut R,
) -> Result<(AliceX3DHResult, KeyPair)> {
    let base_key = KeyPair::generate(csprng);

    let params = AliceParameters {
        our_identity_key: our_identity,
        our_base_key: &base_key,
        their_bundle,
    };

    let result = x3dh_alice(&params, csprng)?;

    Ok((result, base_key))
}

#[cfg(test)]
mod tests {
    use super::super::keys::IdentityKeyPair;
    use super::*;
    use rand::rngs::OsRng;

    fn create_bob_keys<R: CryptoRng + Rng>(
        rng: &mut R,
    ) -> (IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle) {
        let identity = IdentityKeyPair::generate(rng);
        let signed_prekey = SignedPreKey::generate(1, &identity, rng);
        let one_time_prekey = OneTimePreKey::generate(1, rng);

        let bundle = PreKeyBundle::new(
            12345,
            1,
            identity.public_key(),
            signed_prekey.id,
            *signed_prekey.public_key(),
            signed_prekey.signature,
            Some(one_time_prekey.id),
            Some(*one_time_prekey.public_key()),
        );

        (identity, signed_prekey, one_time_prekey, bundle)
    }

    #[test]
    fn test_x3dh_agreement() {
        let mut rng = OsRng;

        // Bob's keys and bundle
        let (bob_identity, bob_signed_prekey, bob_one_time_prekey, bob_bundle) =
            create_bob_keys(&mut rng);

        // Alice initiates
        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let (alice_result, _alice_base_key) =
            x3dh_initiate(&alice_identity, &bob_bundle, &mut rng).unwrap();

        // Bob responds
        let bob_params = BobParameters {
            our_identity_key: &bob_identity,
            our_signed_pre_key: &bob_signed_prekey,
            our_one_time_pre_key: Some(&bob_one_time_prekey),
            their_identity_key: alice_identity.public_key_bytes(),
            their_base_key: &alice_result.ephemeral_public,
        };

        let bob_result = x3dh_bob(&bob_params).unwrap();

        // Both should derive the same root key and chain key
        assert_eq!(alice_result.root_key.key(), bob_result.root_key.key());
        assert_eq!(alice_result.chain_key.key(), bob_result.chain_key.key());
    }

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        let mut rng = OsRng;

        // Bob's keys and bundle (no one-time prekey)
        let bob_identity = IdentityKeyPair::generate(&mut rng);
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity, &mut rng);

        let bob_bundle = PreKeyBundle::new(
            12345,
            1,
            bob_identity.public_key(),
            bob_signed_prekey.id,
            *bob_signed_prekey.public_key(),
            bob_signed_prekey.signature,
            None, // No one-time prekey
            None,
        );

        // Alice initiates
        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let (alice_result, _) = x3dh_initiate(&alice_identity, &bob_bundle, &mut rng).unwrap();

        // Bob responds
        let bob_params = BobParameters {
            our_identity_key: &bob_identity,
            our_signed_pre_key: &bob_signed_prekey,
            our_one_time_pre_key: None,
            their_identity_key: alice_identity.public_key_bytes(),
            their_base_key: &alice_result.ephemeral_public,
        };

        let bob_result = x3dh_bob(&bob_params).unwrap();

        // Both should still derive the same keys
        assert_eq!(alice_result.root_key.key(), bob_result.root_key.key());
        assert_eq!(alice_result.chain_key.key(), bob_result.chain_key.key());
    }

    #[test]
    fn test_x3dh_wrong_identity_fails_verification() {
        let mut rng = OsRng;

        let bob_identity = IdentityKeyPair::generate(&mut rng);
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity, &mut rng);

        // Bundle with wrong identity key
        let wrong_identity = IdentityKeyPair::generate(&mut rng);
        let bad_bundle = PreKeyBundle::new(
            12345,
            1,
            wrong_identity.public_key(), // Wrong identity
            bob_signed_prekey.id,
            *bob_signed_prekey.public_key(),
            bob_signed_prekey.signature,
            None,
            None,
        );

        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let result = x3dh_initiate(&alice_identity, &bad_bundle, &mut rng);

        assert!(result.is_err());
    }

    #[test]
    fn test_x3dh_deterministic() {
        let mut rng = OsRng;

        // Create Bob's keys once
        let bob_identity = IdentityKeyPair::generate(&mut rng);
        let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity, &mut rng);
        let bob_one_time_prekey = OneTimePreKey::generate(1, &mut rng);

        let bob_bundle = PreKeyBundle::new(
            12345,
            1,
            bob_identity.public_key(),
            bob_signed_prekey.id,
            *bob_signed_prekey.public_key(),
            bob_signed_prekey.signature,
            Some(bob_one_time_prekey.id),
            Some(*bob_one_time_prekey.public_key()),
        );

        // Create Alice's identity once
        let alice_identity = IdentityKeyPair::generate(&mut rng);
        let alice_base_key = KeyPair::generate(&mut rng);

        // Two calls with same parameters should produce same result
        let params = AliceParameters {
            our_identity_key: &alice_identity,
            our_base_key: &alice_base_key,
            their_bundle: &bob_bundle,
        };

        let result1 = x3dh_alice(&params, &mut rng).unwrap();
        let result2 = x3dh_alice(&params, &mut rng).unwrap();

        // Results should be deterministic
        assert_eq!(result1.root_key.key(), result2.root_key.key());
        assert_eq!(result1.chain_key.key(), result2.chain_key.key());
    }
}
