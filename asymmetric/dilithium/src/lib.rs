//! Post-quantum digital signatures based on CRYSTALS-Dilithium.
//!
//! This crate exposes a high-level API over [`pqcrypto_dilithium`] (Dilithium2 variant),
//! covering key generation, detached signing, signature verification, and key persistence.
//!
//! # Security level
//!
//! Dilithium2 targets NIST security level 2 (roughly equivalent to AES-128).
//! Use Dilithium3 or Dilithium5 when a higher security margin is required.
//!
//! # Example
//!
//! ```rust,no_run
//! use dilithium::dilithium::{generate_user_key, sign_friendship, verify_friendship};
//!
//! let (pub_key, sec_key) = generate_user_key();
//! let message = b"hello";
//! let sig = sign_friendship(&sec_key, message);
//! assert!(verify_friendship(&pub_key, message, &sig));
//! ```
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]

/// Dilithium signature primitives and key management.
pub mod dilithium;
