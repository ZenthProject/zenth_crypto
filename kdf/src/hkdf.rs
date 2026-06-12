//
// HKDF (HMAC-based Key Derivation Function) - RFC 5869
//

use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

/// HKDF-SHA256 key derivation (RFC 5869).
///
/// Provides extract, expand, and combined derive operations using SHA-256 as the
/// underlying hash. The 32-byte PRK makes this suitable for most key derivation needs.
pub struct HkdfSha256 {
    hkdf: Hkdf<Sha256>,
}

impl HkdfSha256 {
    /// Constructs an [`HkdfSha256`] from optional `salt` and input keying material `ikm`.
    ///
    /// If `salt` is `None`, a zero-filled byte string of hash length is used per RFC 5869.
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        Self {
            hkdf: Hkdf::<Sha256>::new(salt, ikm),
        }
    }

    /// Constructs an [`HkdfSha256`] from a pre-existing pseudorandom key `prk`.
    ///
    /// # Errors
    ///
    /// Returns [`HkdfError::InvalidPrkLength`] if `prk` is shorter than the hash output length.
    pub fn from_prk(prk: &[u8]) -> Result<Self, HkdfError> {
        Hkdf::<Sha256>::from_prk(prk)
            .map(|hkdf| Self { hkdf })
            .map_err(|_| HkdfError::InvalidPrkLength)
    }

    /// Performs only the HKDF extract step and returns the 32-byte PRK.
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
        let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
        prk.into()
    }

    /// Expands the PRK into output keying material written into `okm`.
    ///
    /// `info` binds the derived key to a specific context (e.g. `b"WhisperRatchet"`).
    ///
    /// # Errors
    ///
    /// Returns [`HkdfError::InvalidOutputLength`] if `okm` exceeds `255 * hash_len` bytes.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
        self.hkdf
            .expand(info, okm)
            .map_err(|_| HkdfError::InvalidOutputLength)
    }

    /// Performs the full HKDF extract-then-expand in a single call.
    pub fn derive(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        let hkdf = Self::new(salt, ikm);
        hkdf.expand(info, okm)
    }

    /// Derives a fixed-size key of `N` bytes using extract-then-expand.
    pub fn derive_key<const N: usize>(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
    ) -> Result<[u8; N], HkdfError> {
        let mut okm = [0u8; N];
        Self::derive(salt, ikm, info, &mut okm)?;
        Ok(okm)
    }
}

/// HKDF-SHA384 key derivation (RFC 5869).
///
/// Identical API to [`HkdfSha256`] but uses SHA-384, producing a 48-byte PRK.
/// Suitable when a larger security margin or longer output keys are required.
pub struct HkdfSha384 {
    hkdf: Hkdf<Sha384>,
}

impl HkdfSha384 {
    /// Constructs an [`HkdfSha384`] from optional `salt` and input keying material `ikm`.
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        Self {
            hkdf: Hkdf::<Sha384>::new(salt, ikm),
        }
    }

    /// Constructs an [`HkdfSha384`] from a pre-existing pseudorandom key `prk`.
    ///
    /// # Errors
    ///
    /// Returns [`HkdfError::InvalidPrkLength`] if `prk` is shorter than 48 bytes.
    pub fn from_prk(prk: &[u8]) -> Result<Self, HkdfError> {
        Hkdf::<Sha384>::from_prk(prk)
            .map(|hkdf| Self { hkdf })
            .map_err(|_| HkdfError::InvalidPrkLength)
    }

    /// Performs only the HKDF extract step and returns the 48-byte PRK.
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 48] {
        let (prk, _) = Hkdf::<Sha384>::extract(salt, ikm);
        prk.into()
    }

    /// Expands the PRK into output keying material written into `okm`.
    ///
    /// # Errors
    ///
    /// Returns [`HkdfError::InvalidOutputLength`] if `okm` exceeds `255 * 48` bytes.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
        self.hkdf
            .expand(info, okm)
            .map_err(|_| HkdfError::InvalidOutputLength)
    }

    /// Performs the full HKDF extract-then-expand in a single call.
    pub fn derive(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        let hkdf = Self::new(salt, ikm);
        hkdf.expand(info, okm)
    }

    /// Derives a fixed-size key of `N` bytes using extract-then-expand.
    pub fn derive_key<const N: usize>(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
    ) -> Result<[u8; N], HkdfError> {
        let mut okm = [0u8; N];
        Self::derive(salt, ikm, info, &mut okm)?;
        Ok(okm)
    }
}

/// HKDF-SHA512 key derivation (RFC 5869).
///
/// Identical API to [`HkdfSha256`] but uses SHA-512, producing a 64-byte PRK.
/// Preferred when the highest security margin is required.
pub struct HkdfSha512 {
    hkdf: Hkdf<Sha512>,
}

impl HkdfSha512 {
    /// Constructs an [`HkdfSha512`] from optional `salt` and input keying material `ikm`.
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        Self {
            hkdf: Hkdf::<Sha512>::new(salt, ikm),
        }
    }

    /// Constructs an [`HkdfSha512`] from a pre-existing pseudorandom key `prk`.
    ///
    /// # Errors
    ///
    /// Returns [`HkdfError::InvalidPrkLength`] if `prk` is shorter than 64 bytes.
    pub fn from_prk(prk: &[u8]) -> Result<Self, HkdfError> {
        Hkdf::<Sha512>::from_prk(prk)
            .map(|hkdf| Self { hkdf })
            .map_err(|_| HkdfError::InvalidPrkLength)
    }

    /// Performs only the HKDF extract step and returns the 64-byte PRK.
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 64] {
        let (prk, _) = Hkdf::<Sha512>::extract(salt, ikm);
        prk.into()
    }

    /// Expands the PRK into output keying material written into `okm`.
    ///
    /// # Errors
    ///
    /// Returns [`HkdfError::InvalidOutputLength`] if `okm` exceeds `255 * 64` bytes.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
        self.hkdf
            .expand(info, okm)
            .map_err(|_| HkdfError::InvalidOutputLength)
    }

    /// Performs the full HKDF extract-then-expand in a single call.
    pub fn derive(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), HkdfError> {
        let hkdf = Self::new(salt, ikm);
        hkdf.expand(info, okm)
    }

    /// Derives a fixed-size key of `N` bytes using extract-then-expand.
    pub fn derive_key<const N: usize>(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
    ) -> Result<[u8; N], HkdfError> {
        let mut okm = [0u8; N];
        Self::derive(salt, ikm, info, &mut okm)?;
        Ok(okm)
    }
}

/// Errors returned by HKDF operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    /// The PRK supplied to [`HkdfSha256::from_prk`] (or equivalent) is too short.
    InvalidPrkLength,
    /// The requested output length exceeds `255 * hash_len` bytes.
    InvalidOutputLength,
}

impl std::fmt::Display for HkdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HkdfError::InvalidPrkLength => write!(f, "invalid PRK length"),
            HkdfError::InvalidOutputLength => {
                write!(f, "invalid output length (max 255 * hash_len)")
            }
        }
    }
}

impl std::error::Error for HkdfError {}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Test Case 1
    #[test]
    fn test_hkdf_sha256_rfc5869_case1() {
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];

        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let prk = HkdfSha256::extract(Some(&salt), &ikm);
        assert_eq!(prk, expected_prk);

        let mut okm = [0u8; 42];
        HkdfSha256::derive(Some(&salt), &ikm, &info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm);
    }

    // RFC 5869 Test Case 2 (longer inputs/outputs)
    #[test]
    fn test_hkdf_sha256_rfc5869_case2() {
        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();

        let expected_okm = [
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
            0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
            0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
            0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
            0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
        ];

        let mut okm = [0u8; 82];
        HkdfSha256::derive(Some(&salt), &ikm, &info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm);
    }

    // Test Case 3 (zero-length salt and info)
    #[test]
    fn test_hkdf_sha256_rfc5869_case3() {
        let ikm = [0x0b; 22];

        let expected_okm = [
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
        ];

        let mut okm = [0u8; 42];
        HkdfSha256::derive(None, &ikm, &[], &mut okm).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_derive_key_convenience() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context info";

        let key: [u8; 32] = HkdfSha256::derive_key(Some(salt), ikm, info).unwrap();

        let mut expected = [0u8; 32];
        HkdfSha256::derive(Some(salt), ikm, info, &mut expected).unwrap();

        assert_eq!(key, expected);
    }

    #[test]
    fn test_signal_whisper_message_keys() {
        // Test similar to Signal's WhisperMessageKeys derivation
        let chain_key = [0x8a; 32];
        let info = b"WhisperMessageKeys";

        let mut okm = [0u8; 80]; // 32 + 32 + 16
        HkdfSha256::derive(None, &chain_key, info, &mut okm).unwrap();

        let cipher_key = &okm[0..32];
        let mac_key = &okm[32..64];
        let iv = &okm[64..80];

        assert_eq!(cipher_key.len(), 32);
        assert_eq!(mac_key.len(), 32);
        assert_eq!(iv.len(), 16);
    }
}
