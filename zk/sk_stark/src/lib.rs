//! SK-STARK: Zero-Knowledge Proofs for Secret Key Knowledge
//!
//! This crate provides STARK-based zero-knowledge proofs for proving knowledge
//! of a secret key without revealing it.
//!
//! ## Features
//!
//! - **Poseidon Hash**: STARK-friendly cryptographic hash function
//! - **SK-STARK**: Prove knowledge of secret key where H(sk) = commitment
//! - **Post-Quantum Security**: Based entirely on hash functions
//!
//! ## Usage
//!
//! ```no_run
//! use sk_stark::{prove_secret_key, verify_secret_key, compute_commitment};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let secret_key = b"my_secret_key_data...";
//!     let domain = b"zenth_auth_v1\0\0\0"; // Must be exactly 16 bytes
//!
//!     let proof = prove_secret_key(secret_key, domain)?;
//!
//!     verify_secret_key(&proof, None)?;
//!
//!     let commitment = compute_commitment(secret_key, domain);
//!     verify_secret_key(&proof, Some(&commitment))?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Security
//!
//! - 128-bit security level
//! - Post-quantum secure (STARK + Poseidon)
//! - Zero-knowledge: verifier learns nothing about the secret
//!
//! ## Performance
//!
//! Proof generation: ~100ms - 1s depending on secret size
//! Verification: ~10-50ms
//! Proof size: ~50-200 KB

pub mod poseidon;
pub mod secret_key;


pub use secret_key::{
    compute_commitment, prove_secret_key, verify_secret_key, SecretKeyError, SecretKeyProof,
    SecretKeyPublicInputs,
};

pub use poseidon::{
    bytes_to_elements, poseidon_hash, poseidon_hash_bytes, poseidon_hash_two, PoseidonState,
};
