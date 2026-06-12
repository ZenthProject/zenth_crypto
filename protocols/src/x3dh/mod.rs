//! Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
//!
//! Implements the X3DH key agreement protocol as specified by Signal, with optional
//! PQXDH (Post-Quantum X3DH) support via Kyber KEM integration.
//!
//! ## Protocol Overview
//!
//! X3DH establishes a shared secret between two parties (Alice and Bob) where:
//! - Bob has published a "pre-key bundle" to a server
//! - Alice fetches Bob's bundle and performs key agreement
//! - Both parties derive the same shared secret for Double Ratchet
//!
//! ## Security Properties
//!
//! - **Mutual Authentication**: Both parties prove identity via DH operations
//! - **Forward Secrecy**: Ephemeral keys ensure past messages stay secure
//! - **Post-Quantum Security** (PQXDH): Kyber KEM protects against quantum attacks
//!
//! ## Usage
//!
//! ```rust,no_run
//! use protocols::x3dh::{IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle};
//! use protocols::x3dh::{x3dh_initiate, x3dh_bob, BobParameters};
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//!
//! // Bob generates and publishes his keys
//! let bob_identity = IdentityKeyPair::generate(&mut rng);
//! let bob_signed_prekey = SignedPreKey::generate(1, &bob_identity, &mut rng);
//! let bob_one_time_prekey = OneTimePreKey::generate(1, &mut rng);
//!
//! let bundle = PreKeyBundle::new(
//!     12345, 1,
//!     bob_identity.public_key(),
//!     bob_signed_prekey.id,
//!     *bob_signed_prekey.public_key(),
//!     bob_signed_prekey.signature,
//!     Some(bob_one_time_prekey.id),
//!     Some(*bob_one_time_prekey.public_key()),
//! );
//!
//! // Alice fetches bundle and initiates
//! let alice_identity = IdentityKeyPair::generate(&mut rng);
//! let (alice_result, alice_base_key) = x3dh_initiate(&alice_identity, &bundle, &mut rng).unwrap();
//!
//! // Bob responds
//! let bob_params = BobParameters {
//!     our_identity_key: &bob_identity,
//!     our_signed_pre_key: &bob_signed_prekey,
//!     our_one_time_pre_key: Some(&bob_one_time_prekey),
//!     their_identity_key: alice_identity.public_key_bytes(),
//!     their_base_key: &alice_result.ephemeral_public,
//! };
//! let bob_result = x3dh_bob(&bob_params).unwrap();
//!
//! // Both now have matching root_key and chain_key for Double Ratchet
//! assert_eq!(alice_result.root_key.key(), bob_result.root_key.key());
//! ```

pub mod agreement;
pub mod bundle;
pub mod keys;

// Re-exports for convenience
pub use agreement::{
    x3dh_alice, x3dh_bob, x3dh_initiate, AliceParameters, AliceX3DHResult, BobParameters,
    BobX3DHResult,
};
pub use bundle::{PreKeyBundle, PreKeyBundleBuilder};
pub use keys::{
    IdentityKey, IdentityKeyPair, KeyPair, OneTimePreKey, SignedPreKey, EC_KEY_SIZE, SIGNATURE_SIZE,
};
