//! Hash-based post-quantum signatures using the Leighton-Micali Signature scheme (LMS/HSS).
//!
//! LMS is a stateful hash-based signature scheme standardised in [RFC 8554].
//! Unlike lattice-based schemes, its security relies solely on the collision resistance
//! of an underlying hash function (SHA-256 here), making it a conservative choice for
//! long-term post-quantum security.
//!
//! # Statefulness
//!
//! LMS is **stateful**: each private key supports at most `2^height` signatures.
//! Once exhausted, the key must be replaced. Always use [`lms::LmsKeyPair`] rather
//! than the raw [`lms::sign`] function to benefit from built-in exhaustion tracking.
//!
//! # Example
//!
//! ```rust,no_run
//! use lms::lms::generate_keypair;
//!
//! let keypair = generate_keypair().expect("key generation failed");
//! let message = b"hello";
//! let sig = keypair.sign(message).expect("signing failed");
//! keypair.verify(message, &sig).expect("verification failed");
//! ```
//!
//! [RFC 8554]: https://www.rfc-editor.org/rfc/rfc8554
pub mod lms;
