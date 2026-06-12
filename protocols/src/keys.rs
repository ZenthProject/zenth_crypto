//
// Zenth Double Ratchet Protocol - Key Types
//
// Implements ChainKey, RootKey, and MessageKeys as per the Signal specification.
//

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use kdf::{derive_arrays, hmac_sha256};

use crate::consts::{
    CHAIN_KEY_SEED, IV_SIZE, KDF_MESSAGE_INFO, KDF_RK_INFO, KEY_SIZE, MAC_KEY_SIZE,
    MESSAGE_KEY_SEED,
};
use crate::errors::{RatchetError, Result};

/// Full IV size from HKDF derivation (16 bytes)
const DERIVED_IV_SIZE: usize = 16;

/// Message keys derived from a chain key.
///
/// Contains the cipher key, MAC key, and IV needed to encrypt/decrypt a single message.
/// These keys are used once and then discarded.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKeys {
    cipher_key: [u8; KEY_SIZE],
    mac_key: [u8; MAC_KEY_SIZE],
    iv: [u8; DERIVED_IV_SIZE], // Full 16 bytes from HKDF, we use first 12 for AES-GCM
    counter: u32,
}

impl MessageKeys {
    /// Derive message keys from input key material using HKDF.
    ///
    /// # Arguments
    /// * `input_key_material` - The seed derived from chain key (HMAC(CK, 0x01))
    /// * `optional_salt` - Optional salt for HKDF (used for post-quantum ratchet)
    /// * `counter` - The message counter (for ordering)
    pub fn derive(input_key_material: &[u8], optional_salt: Option<&[u8]>, counter: u32) -> Self {
        // Derive 80 bytes: 32 (cipher) + 32 (mac) + 16 (iv)
        let (cipher_key, mac_key, iv): ([u8; KEY_SIZE], [u8; MAC_KEY_SIZE], [u8; DERIVED_IV_SIZE]) =
            derive_arrays(|okm| {
                Hkdf::<Sha256>::new(optional_salt, input_key_material)
                    .expand(KDF_MESSAGE_INFO, okm)
                    .expect("valid output length for message keys");
            });

        Self {
            cipher_key,
            mac_key,
            iv,
            counter,
        }
    }

    /// Get the cipher key (32 bytes for AES-256)
    #[inline]
    pub fn cipher_key(&self) -> &[u8; KEY_SIZE] {
        &self.cipher_key
    }

    /// Get the MAC key (32 bytes)
    #[inline]
    pub fn mac_key(&self) -> &[u8; MAC_KEY_SIZE] {
        &self.mac_key
    }

    /// Get the IV for AES-GCM (12 bytes, truncated from derived 16 bytes)
    pub fn iv(&self) -> [u8; IV_SIZE] {
        let mut iv12 = [0u8; IV_SIZE];
        iv12.copy_from_slice(&self.iv[..IV_SIZE]);
        iv12
    }

    /// Get the full derived IV (16 bytes)
    #[inline]
    pub fn iv_full(&self) -> &[u8; DERIVED_IV_SIZE] {
        &self.iv
    }

    /// Get the message counter
    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// Create MessageKeys from raw components (for deserialization).
    ///
    /// # Arguments
    /// * `cipher_key` - 32-byte cipher key
    /// * `mac_key` - 32-byte MAC key
    /// * `iv` - 16-byte IV (full size, truncated to 12 for AES-GCM)
    /// * `counter` - Message counter
    pub fn from_raw(
        cipher_key: [u8; KEY_SIZE],
        mac_key: [u8; MAC_KEY_SIZE],
        iv: [u8; DERIVED_IV_SIZE],
        counter: u32,
    ) -> Self {
        Self {
            cipher_key,
            mac_key,
            iv,
            counter,
        }
    }
}

/// Chain key for the symmetric ratchet.
///
/// Each message advances the chain key using HMAC(CK, 0x02).
/// Message keys are derived using HMAC(CK, 0x01) then HKDF expansion.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey {
    key: [u8; KEY_SIZE],
    index: u32,
}

impl ChainKey {
    /// Create a new chain key with the given key material and index.
    pub fn new(key: [u8; KEY_SIZE], index: u32) -> Self {
        Self { key, index }
    }

    /// Get the raw key bytes
    #[inline]
    pub fn key(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Get the current index (message counter)
    #[inline]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Derive the next chain key by computing HMAC(CK, 0x02).
    ///
    /// This advances the symmetric ratchet by one step.
    pub fn next(&self) -> Result<Self> {
        let new_index = self
            .index
            .checked_add(1)
            .ok_or(RatchetError::CounterOverflow)?;

        Ok(Self {
            key: hmac_sha256(&self.key, &CHAIN_KEY_SEED),
            index: new_index,
        })
    }

    /// Derive the message key seed by computing HMAC(CK, 0x01).
    ///
    /// This seed is then expanded via HKDF to produce the actual message keys.
    fn message_key_seed(&self) -> [u8; KEY_SIZE] {
        hmac_sha256(&self.key, &MESSAGE_KEY_SEED)
    }

    /// Derive message keys for encrypting/decrypting a message at this chain position.
    ///
    /// # Arguments
    /// * `pq_salt` - Optional post-quantum key material to mix in
    pub fn message_keys(&self, pq_salt: Option<&[u8]>) -> MessageKeys {
        let seed = self.message_key_seed();
        MessageKeys::derive(&seed, pq_salt, self.index)
    }
}

impl std::fmt::Debug for ChainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainKey")
            .field("index", &self.index)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Root key for the DH ratchet.
///
/// The root key is updated each time a new DH exchange occurs.
/// It produces a new root key and a new chain key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey {
    key: [u8; KEY_SIZE],
}

impl RootKey {
    /// Create a new root key from raw bytes.
    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Get the raw key bytes
    #[inline]
    pub fn key(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Perform a DH ratchet step.
    ///
    /// Combines the current root key with a new DH shared secret to produce:
    /// - A new root key
    /// - A new chain key (for sending or receiving)
    ///
    /// # Arguments
    /// * `dh_output` - The result of a DH key agreement (32 bytes)
    ///
    /// # Returns
    /// A tuple of (new_root_key, new_chain_key)
    pub fn create_chain(&self, dh_output: &[u8; KEY_SIZE]) -> (RootKey, ChainKey) {
        let (root_key, chain_key, []): ([u8; KEY_SIZE], [u8; KEY_SIZE], [u8; 0]) =
            derive_arrays(|bytes| {
                Hkdf::<Sha256>::new(Some(&self.key), dh_output)
                    .expand(KDF_RK_INFO, bytes)
                    .expect("valid output length for ratchet keys");
            });

        (RootKey { key: root_key }, ChainKey::new(chain_key, 0))
    }
}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Display for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only show first 4 bytes as hex for debugging
        write!(f, "RootKey({}...)", hex::encode(&self.key[..4]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_derivation() {
        // Test vector from Signal's test suite
        let seed = [
            0x8au8, 0xb7, 0x2d, 0x6f, 0x4c, 0xc5, 0xac, 0x0d, 0x38, 0x7e, 0xaf, 0x46, 0x33, 0x78,
            0xdd, 0xb2, 0x8e, 0xdd, 0x07, 0x38, 0x5b, 0x1c, 0xb0, 0x12, 0x50, 0xc7, 0x15, 0x98,
            0x2e, 0x7a, 0xd4, 0x8f,
        ];

        let expected_message_key = [
            0xbfu8, 0x51, 0xe9, 0xd7, 0x5e, 0x0e, 0x31, 0x03, 0x10, 0x51, 0xf8, 0x2a, 0x24, 0x91,
            0xff, 0xc0, 0x84, 0xfa, 0x29, 0x8b, 0x77, 0x93, 0xbd, 0x9d, 0xb6, 0x20, 0x05, 0x6f,
            0xeb, 0xf4, 0x52, 0x17,
        ];

        let expected_mac_key = [
            0xc6u8, 0xc7, 0x7d, 0x6a, 0x73, 0xa3, 0x54, 0x33, 0x7a, 0x56, 0x43, 0x5e, 0x34, 0x60,
            0x7d, 0xfe, 0x48, 0xe3, 0xac, 0xe1, 0x4e, 0x77, 0x31, 0x4d, 0xc6, 0xab, 0xc1, 0x72,
            0xe7, 0xa7, 0x03, 0x0b,
        ];

        let expected_next_chain = [
            0x28u8, 0xe8, 0xf8, 0xfe, 0xe5, 0x4b, 0x80, 0x1e, 0xef, 0x7c, 0x5c, 0xfb, 0x2f, 0x17,
            0xf3, 0x2c, 0x7b, 0x33, 0x44, 0x85, 0xbb, 0xb7, 0x0f, 0xac, 0x6e, 0xc1, 0x03, 0x42,
            0xa2, 0x46, 0xd1, 0x5d,
        ];

        let chain_key = ChainKey::new(seed, 0);

        assert_eq!(chain_key.key(), &seed);
        assert_eq!(chain_key.index(), 0);

        let msg_keys = chain_key.message_keys(None);
        assert_eq!(msg_keys.cipher_key(), &expected_message_key);
        assert_eq!(msg_keys.mac_key(), &expected_mac_key);
        assert_eq!(msg_keys.counter(), 0);

        let next_chain = chain_key.next().unwrap();
        assert_eq!(next_chain.key(), &expected_next_chain);
        assert_eq!(next_chain.index(), 1);
    }

    #[test]
    fn test_chain_key_counter_increment() {
        let chain_key = ChainKey::new([0u8; 32], 0);

        let chain1 = chain_key.next().unwrap();
        assert_eq!(chain1.index(), 1);

        let chain2 = chain1.next().unwrap();
        assert_eq!(chain2.index(), 2);

        // Keys should be different
        assert_ne!(chain_key.key(), chain1.key());
        assert_ne!(chain1.key(), chain2.key());
    }

    #[test]
    fn test_root_key_create_chain() {
        let root_key = RootKey::new([0x42u8; 32]);
        let dh_output = [0x13u8; 32];

        let (new_root, chain_key) = root_key.create_chain(&dh_output);

        // Should produce different keys
        assert_ne!(root_key.key(), new_root.key());
        assert_ne!(new_root.key(), chain_key.key());

        // Chain should start at 0
        assert_eq!(chain_key.index(), 0);
    }

    #[test]
    fn test_root_key_deterministic() {
        let root1 = RootKey::new([0x42u8; 32]);
        let root2 = RootKey::new([0x42u8; 32]);
        let dh_output = [0x13u8; 32];

        let (new_root1, chain1) = root1.create_chain(&dh_output);
        let (new_root2, chain2) = root2.create_chain(&dh_output);

        assert_eq!(new_root1.key(), new_root2.key());
        assert_eq!(chain1.key(), chain2.key());
    }

    #[test]
    fn test_message_keys_derive() {
        let ikm = [0xAB; 32];
        let keys1 = MessageKeys::derive(&ikm, None, 0);
        let keys2 = MessageKeys::derive(&ikm, None, 1);

        // Same IKM should produce same cipher/mac keys
        assert_eq!(keys1.cipher_key(), keys2.cipher_key());
        assert_eq!(keys1.mac_key(), keys2.mac_key());

        // But different counters
        assert_eq!(keys1.counter(), 0);
        assert_eq!(keys2.counter(), 1);
    }

    #[test]
    fn test_message_keys_with_salt() {
        let ikm = [0xAB; 32];
        let salt = [0xCD; 32];

        let keys_no_salt = MessageKeys::derive(&ikm, None, 0);
        let keys_with_salt = MessageKeys::derive(&ikm, Some(&salt), 0);

        // Different salt should produce different keys
        assert_ne!(keys_no_salt.cipher_key(), keys_with_salt.cipher_key());
    }
}
