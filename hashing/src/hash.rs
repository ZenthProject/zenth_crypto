//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crc32fast::Hasher;
use errors::error::{Error, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Keccak512, Sha3_256, Sha3_512};

/// Algorithm-agnostic HMAC wrapper supporting SHA-1, SHA-256, SHA3-256, and SHA3-512.
///
/// Constructed once with a key, updated with any number of input chunks, then finalised
/// to produce the authentication tag.
#[derive(Clone)]
pub enum CryptographicMac {
    /// HMAC-SHA-256.
    HmacSha256(Hmac<Sha256>),
    /// HMAC-SHA-1.
    HmacSha1(Hmac<Sha1>),
    /// HMAC-SHA3-256.
    HmacSha3_256(Hmac<Sha3_256>),
    /// HMAC-SHA3-512.
    HmacSha3_512(Hmac<Sha3_512>),
}

impl CryptographicMac {
    /// Constructs a [`CryptographicMac`] for the given algorithm and key.
    ///
    /// Accepted `algo` values (case-insensitive variants listed):
    /// `"HmacSha1"`, `"HmacSha256"`, `"HmacSha3-256"`, `"HmacSha3-512"`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownAlgorithm`] if `algo` is not recognised.
    pub fn new(algo: &str, key: &[u8]) -> Result<Self> {
        match algo {
            "HMACSha1" | "HmacSha1" => Ok(Self::HmacSha1(
                Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha256" | "HmacSha256" => Ok(Self::HmacSha256(
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha3-256" | "HmacSha3-256" => Ok(Self::HmacSha3_256(
                Hmac::<Sha3_256>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha3-512" | "HmacSha3-512" => Ok(Self::HmacSha3_512(
                Hmac::<Sha3_512>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            _ => Err(Error::UnknownAlgorithm("MAC", algo.to_string())),
        }
    }

    /// Feeds `input` into the MAC state.
    pub fn update(&mut self, input: &[u8]) {
        match self {
            Self::HmacSha1(sha1) => sha1.update(input),
            Self::HmacSha256(sha256) => sha256.update(input),
            Self::HmacSha3_256(sha3_256) => sha3_256.update(input),
            Self::HmacSha3_512(sha3_512) => sha3_512.update(input),
        }
    }

    /// Feeds `input` into the MAC state and returns `&mut self` for method chaining.
    pub fn update_and_get(&mut self, input: &[u8]) -> &mut Self {
        self.update(input);
        self
    }

    /// Finalises the MAC and returns the authentication tag as a byte vector.
    ///
    /// The internal state is cloned before finalisation so this instance can
    /// continue to be updated after the call.
    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::HmacSha1(sha1) => sha1.clone().finalize().into_bytes().to_vec(),
            Self::HmacSha256(sha256) => sha256.clone().finalize().into_bytes().to_vec(),
            Self::HmacSha3_256(sha3_256) => sha3_256.clone().finalize().into_bytes().to_vec(),
            Self::HmacSha3_512(sha3_512) => sha3_512.clone().finalize().into_bytes().to_vec(),
        }
    }
}

/// Algorithm-agnostic digest wrapper with support for iterated hashing.
///
/// Input is accumulated in an internal buffer via [`update`][Self::update].
/// Calling [`finalize`][Self::finalize] runs the chosen algorithm for `rounds` iterations,
/// each pass feeding the output of the previous one as input. With `rounds = 1` this
/// behaves as a standard single-pass digest.
///
/// Supported algorithms: SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512, Keccak-512, MD5, CRC32.
#[derive(Clone)]
pub enum CryptographicHash {
    /// SHA-1 digest with iteration support.
    Sha1 {
        hasher: Sha1,
        rounds: usize,
        buffer: Vec<u8>,
    },
    /// SHA-256 digest with iteration support.
    Sha256 {
        hasher: Sha256,
        rounds: usize,
        buffer: Vec<u8>,
    },
    /// SHA-512 digest with iteration support.
    Sha512 {
        hasher: Sha512,
        rounds: usize,
        buffer: Vec<u8>,
    },
    /// SHA3-256 digest with iteration support.
    Sha3_256 {
        hasher: Sha3_256,
        rounds: usize,
        buffer: Vec<u8>,
    },
    /// SHA3-512 digest with iteration support.
    Sha3_512 {
        hasher: Sha3_512,
        rounds: usize,
        buffer: Vec<u8>,
    },
    /// Keccak-512 digest with iteration support.
    Keccak512 {
        hasher: Keccak512,
        rounds: usize,
        buffer: Vec<u8>,
    },
    /// MD5 digest with iteration support. Not suitable for security-critical applications.
    Md5 { rounds: usize, buffer: Vec<u8> },
    /// CRC32 checksum with iteration support. Not a cryptographic primitive.
    CRC32 { rounds: usize, buffer: Vec<u8> },
}

impl CryptographicHash {
    /// Constructs a [`CryptographicHash`] for the given algorithm and iteration count.
    ///
    /// `rounds` controls how many times the digest is applied over its own output.
    /// Pass `1` for a standard single-pass hash.
    ///
    /// Accepted `algo` values include: `"SHA-256"`, `"SHA3-512"`, `"Keccak512"`,
    /// `"MD5"`, `"CRC32"`, and several case/separator variants of each.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownAlgorithm`] if `algo` is not recognised.
    pub fn new(algo: &str, rounds: usize) -> Result<Self> {
        match algo {
            "SHA-1" | "SHA1" | "Sha1" => Ok(Self::Sha1 {
                hasher: Sha1::new(),
                rounds,
                buffer: vec![],
            }),
            "SHA-256" | "SHA256" | "Sha256" => Ok(Self::Sha256 {
                hasher: Sha256::new(),
                rounds,
                buffer: vec![],
            }),
            "SHA-512" | "SHA512" | "Sha512" => Ok(Self::Sha512 {
                hasher: Sha512::new(),
                rounds,
                buffer: vec![],
            }),
            "SHA3-256" | "SHA3_256" | "Sha3-256" | "Sha3_256" => Ok(Self::Sha3_256 {
                hasher: Sha3_256::new(),
                rounds,
                buffer: vec![],
            }),
            "SHA3-512" | "Sha3_512" => Ok(Self::Sha3_512 {
                hasher: Sha3_512::new(),
                rounds,
                buffer: vec![],
            }),
            "Keccak512" | "KECCAK512" | "Keccak-512" | "KECCAK-512" => Ok(Self::Keccak512 {
                hasher: Keccak512::new(),
                rounds,
                buffer: vec![],
            }),
            "MD5" | "Md5" | "MD-5" | "Md-5" => Ok(Self::Md5 {
                rounds,
                buffer: vec![],
            }),
            "CRC32" | "CRC-32" | "Crc32" | "Crc-32" => Ok(Self::CRC32 {
                rounds,
                buffer: vec![],
            }),
            _ => Err(Error::UnknownAlgorithm("digest", algo.to_string())),
        }
    }

    /// Appends `input` to the internal accumulation buffer.
    pub fn update(&mut self, input: &[u8]) {
        match self {
            Self::Sha1 { buffer, .. }
            | Self::Sha256 { buffer, .. }
            | Self::Sha512 { buffer, .. }
            | Self::Sha3_256 { buffer, .. }
            | Self::Sha3_512 { buffer, .. }
            | Self::Keccak512 { buffer, .. }
            | Self::Md5 { buffer, .. }
            | Self::CRC32 { buffer, .. } => buffer.extend_from_slice(input),
        }
    }

    /// Applies the chosen digest `rounds` times over the accumulated buffer and returns the result.
    ///
    /// Each round feeds the output of the previous one as input. The internal buffer is
    /// not reset, so further [`update`][Self::update] calls after finalisation are possible
    /// but will re-include previously processed data.
    pub fn finalize(&mut self) -> Vec<u8> {
        match self {
            Self::Sha1 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha1::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Sha256 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha256::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Sha512 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha512::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Sha3_256 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha3_256::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Sha3_512 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Sha3_512::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Keccak512 { rounds, buffer, .. } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut h = Keccak512::new();
                    h.update(&result);
                    result = h.finalize().to_vec();
                }
                result
            }
            Self::Md5 { rounds, buffer } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    result = md5::compute(&result).0.to_vec();
                }
                result
            }
            Self::CRC32 { rounds, buffer } => {
                let mut result = buffer.clone();
                for _ in 0..*rounds {
                    let mut hasher = Hasher::new();
                    hasher.update(&result);
                    let crc = hasher.finalize();
                    result = crc.to_le_bytes().to_vec();
                }
                result
            }
        }
    }
}
