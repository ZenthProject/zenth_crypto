//! Encoding and decoding utilities for binary data transport formats.
//!
//! This crate provides trait-based, testable wrappers over three common
//! text-encoding formats used throughout the workspace:
//!
//! | Module       | Format  |                  Use case                   |
//! |--------------|---------|---------------------------------------------|
//! | [`base64`]   | Base64  | Binary blobs, ciphertexts, RSA payloads     |
//! | [`hex`]      | Hex     | Key fingerprints, digests, debug output     |
//! | [`pem`]      | PEM     | Certificate and key file interchange        |

pub mod base64;
pub mod hex;
pub mod pem;
