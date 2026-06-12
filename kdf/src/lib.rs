//! Key derivation functions for cryptographic protocols.
//!
//! | Module       | Primitive                  | Use case                                      |
//! |--------------|----------------------------|-----------------------------------------------|
//! | [`argon2id`] | Argon2id (OWASP params)    | Password hashing and key stretching           |
//! | [`hkdf`]     | HKDF-SHA256/384/512        | Key expansion from high-entropy secrets       |
//! | [`crypto`]   | HMAC-SHA256                | Chain key derivation (Double Ratchet)         |
//! | [`arrays`]   | Split KDF output           | Derive multiple fixed-size keys in one pass   |

pub mod argon2id;
pub mod arrays;
pub mod crypto;
pub mod hkdf;

pub use arrays::{derive_arrays, derive_arrays_2, try_derive_arrays};
pub use crypto::hmac_sha256;
pub use hkdf::{HkdfError, HkdfSha256, HkdfSha384, HkdfSha512};
