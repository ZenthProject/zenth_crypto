//! Zenth Protocols
//!
//! Implementation of cryptographic protocols including:
//! - Double Ratchet messaging protocol (Signal-compatible)
//! - Key exchange protocols
//!
//! # Double Ratchet Protocol
//!
//! The Double Ratchet protocol provides end-to-end encryption with:
//! - Perfect forward secrecy (compromised keys don't reveal past messages)
//! - Break-in recovery (compromised keys don't reveal future messages)
//! - Out-of-order message handling
//!
//! ## Example
//!
//! ```rust,no_run
//! use protocols::{SessionState, SessionCipher};
//! use exchange::curve25519::PrivateKey;
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//!
//! // Shared secret from X3DH key agreement
//! let shared_secret = [0u8; 32]; // In practice, from X3DH
//!
//! // Bob's prekey (published to server)
//! let bob_prekey = PrivateKey::new(&mut rng);
//! let bob_prekey_public = bob_prekey.derive_public_key_bytes();
//!
//! // Alice initializes her session
//! let alice_state = SessionState::initialize_alice(
//!     &shared_secret,
//!     &bob_prekey_public,
//!     &mut rng,
//! ).unwrap();
//!
//! // Bob initializes his session
//! let bob_state = SessionState::initialize_bob(
//!     &shared_secret,
//!     bob_prekey,
//! ).unwrap();
//!
//! // Create ciphers
//! let mut alice = SessionCipher::new(alice_state);
//! let mut bob = SessionCipher::new(bob_state);
//!
//! // Alice encrypts a message
//! let encrypted = alice.encrypt(b"Hello, Bob!").unwrap();
//!
//! // Bob decrypts
//! let plaintext = bob.decrypt(&encrypted, &mut rng).unwrap();
//! assert_eq!(plaintext, b"Hello, Bob!");
//! ```

#![warn(clippy::unwrap_used)]
#![deny(unsafe_code)]

pub mod cipher;
pub mod consts;
pub mod errors;
pub mod keys;
pub mod pqxdh;
pub mod state;
pub mod x3dh;

// Re-exports for convenience
pub use cipher::{EncryptedMessage, SessionCipher};
pub use consts::*;
pub use errors::{RatchetError, Result};
pub use keys::{ChainKey, MessageKeys, RootKey};
pub use state::{ExportedSessionState, MessageHeader, SessionState};

// X3DH re-exports
pub use x3dh::{
    x3dh_alice, x3dh_bob, x3dh_initiate, AliceParameters, AliceX3DHResult, BobParameters,
    BobX3DHResult, IdentityKey, IdentityKeyPair, KeyPair, OneTimePreKey, PreKeyBundle,
    PreKeyBundleBuilder, SignedPreKey,
};

// PQXDH re-exports (Post-Quantum X3DH with Kyber)
pub use pqxdh::{
    pqxdh_alice, pqxdh_bob, AlicePQXDHResult, BobPQXDHParameters, BobPQXDHResult, PQPreKeyBundle,
    SignedKyberPreKey, KYBER_TYPE,
};
