//! Cryptographic hashing and MAC primitives.
//!
//! This crate provides two algorithm-agnostic types:
//!
//! - [`hash::CryptographicHash`] — iterated digest (SHA-1, SHA-256, SHA-512, SHA3-256,
//!   SHA3-512, Keccak-512, MD5, CRC32).
//! - [`hash::CryptographicMac`] — keyed MAC (HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA3-256,
//!   HMAC-SHA3-512).
//!
//! Both types are constructed from a string algorithm name and updated incrementally,
//! following the same absorb → finalize pattern.

pub mod hash;
