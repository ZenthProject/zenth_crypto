//! Asymmetric cryptography primitives.
//!
//! This crate re-exports all asymmetric sub-crates available in the workspace:
//!
//! |   Sub-crate   |       Scheme        |              Purpose               |
//! |---------------|---------------------|------------------------------------|
//! | [`dilithium`] | CRYSTALS-Dilithium2 | Post-quantum digital signatures    |
//! | [`lms`]       | LMS/HSS (RFC 8554)  | Hash-based post-quantum signatures |
//! | [`rsa_oaep`]  | RSA-4096 + OAEP     | Classical asymmetric encryption    |

pub use dilithium;
pub use lms;
pub use rsa_oaep;
