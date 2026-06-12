//! RSA-4096 encryption and decryption with OAEP padding.
//!
//! This crate provides a high-level wrapper around RSA-4096 using Optimal
//! Asymmetric Encryption Padding (OAEP) with SHA-512 as the hash function,
//! as specified in [PKCS #1 v2.2].
//!
//! # Security note
//!
//! RSA is a classical scheme and is **not** quantum-resistant. For long-term
//! confidentiality against quantum adversaries, pair this with a post-quantum
//! key encapsulation mechanism (e.g., ML-KEM / Kyber).
//!
//! # Example
//!
//! ```rust,no_run
//! use rsa_oaep::rsa4096::Rsa4096;
//!
//! let rsa = Rsa4096::new();
//! let ciphertext = rsa.encrypt(b"secret message");
//! let plaintext = rsa.decrypt(&ciphertext);
//! assert_eq!(plaintext, b"secret message");
//! ```
//!
//! [PKCS #1 v2.2]: https://www.rfc-editor.org/rfc/rfc8017
pub mod rsa4096;
