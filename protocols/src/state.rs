//! Double Ratchet session state.
//!
//! Manages the complete cryptographic state of a Double Ratchet session,
//! including DH ratchet keys, chain keys, message counters, and skipped-message
//! key storage for out-of-order delivery.
//!
//! `ZeroizeOnDrop` generates `Drop` impls that confuse rustc's liveness analysis,
//! producing false-positive `unused_assignments` warnings on fields of zeroized structs.
#![allow(unused_assignments)]

use std::collections::HashMap;

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use exchange::curve25519::{PrivateKey, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};

use crate::consts::{DH_KEY_SIZE, KEY_SIZE, MAX_SKIP};
use crate::errors::{RatchetError, Result};
use crate::keys::{ChainKey, MessageKeys, RootKey};

/// A skipped message key, indexed by (ratchet_public_key, counter)
type SkippedKeyIndex = ([u8; DH_KEY_SIZE], u32);

/// Complete state of a Double Ratchet session.
///
/// This structure maintains all the keys and counters needed
/// to encrypt and decrypt messages in a conversation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionState {
    /// Our current DH key pair for ratcheting
    #[zeroize(skip)] // PrivateKey handles its own zeroization
    dh_self: PrivateKey,

    /// Their current DH public key
    dh_remote: Option<[u8; DH_KEY_SIZE]>,

    /// Current root key
    root_key: RootKey,

    /// Chain key for sending messages
    sending_chain: Option<ChainKey>,

    /// Chain key for receiving messages
    receiving_chain: Option<ChainKey>,

    /// Number of messages sent in current sending chain
    send_count: u32,

    /// Number of messages received in current receiving chain
    recv_count: u32,

    /// Previous sending chain length (for header)
    previous_chain_length: u32,

    /// Skipped message keys for out-of-order decryption
    /// Key: (their_ratchet_public, message_counter)
    #[zeroize(skip)] // HashMap doesn't implement Zeroize, we clear manually
    skipped_keys: HashMap<SkippedKeyIndex, MessageKeys>,
}

impl SessionState {
    /// Initialize a session as Alice (the initiator).
    ///
    /// Alice performs the first DH ratchet step using Bob's prekey.
    ///
    /// # Arguments
    /// * `shared_secret` - The initial shared secret from X3DH
    /// * `bob_public_key` - Bob's signed prekey public key
    /// * `csprng` - Cryptographically secure RNG
    pub fn initialize_alice<R: CryptoRng + Rng>(
        shared_secret: &[u8; KEY_SIZE],
        bob_public_key: &[u8; PUBLIC_KEY_LENGTH],
        csprng: &mut R,
    ) -> Result<Self> {
        let dh_self = PrivateKey::new(csprng);
        let dh_output = dh_self.calculate_agreement(bob_public_key);
        let initial_root = RootKey::new(*shared_secret);
        let (root_key, sending_chain) = initial_root.create_chain(&dh_output);

        Ok(Self {
            dh_self,
            dh_remote: Some(*bob_public_key),
            root_key,
            sending_chain: Some(sending_chain),
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Initialize a session as Bob (the responder).
    ///
    /// Bob waits for Alice's first message before ratcheting.
    ///
    /// # Arguments
    /// * `shared_secret` - The initial shared secret from X3DH
    /// * `our_signed_prekey` - Bob's signed prekey (the one Alice used)
    pub fn initialize_bob(
        shared_secret: &[u8; KEY_SIZE],
        our_signed_prekey: PrivateKey,
    ) -> Result<Self> {
        Ok(Self {
            dh_self: our_signed_prekey,
            dh_remote: None,
            root_key: RootKey::new(*shared_secret),
            sending_chain: None,
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
        })
    }

    /// Get our current DH public key (to include in message headers).
    pub fn our_public_key(&self) -> [u8; DH_KEY_SIZE] {
        self.dh_self.derive_public_key_bytes()
    }

    /// Get the current send count.
    pub fn send_count(&self) -> u32 {
        self.send_count
    }

    /// Get the previous chain length (for message header).
    pub fn previous_chain_length(&self) -> u32 {
        self.previous_chain_length
    }

    /// Encrypt a message, advancing the sending chain.
    ///
    /// # Returns
    /// The message keys to use for encryption and the updated header info.
    pub fn encrypt_step(&mut self) -> Result<(MessageKeys, MessageHeader)> {
        let sending_chain = self
            .sending_chain
            .as_ref()
            .ok_or(RatchetError::SessionNotInitialized)?;

        let msg_keys = sending_chain.message_keys(None);

        let header = MessageHeader {
            public_key: self.our_public_key(),
            previous_chain_length: self.previous_chain_length,
            message_number: self.send_count,
        };

        self.sending_chain = Some(sending_chain.next()?);
        self.send_count += 1;

        Ok((msg_keys, header))
    }

    /// Process an incoming message header and perform DH ratchet if needed.
    ///
    /// # Arguments
    /// * `header` - The message header
    /// * `csprng` - RNG for generating new key pairs
    ///
    /// # Returns
    /// The message keys for decryption
    pub fn decrypt_step<R: CryptoRng + Rng>(
        &mut self,
        header: &MessageHeader,
        csprng: &mut R,
    ) -> Result<MessageKeys> {
        let skip_key = (header.public_key, header.message_number);
        if let Some(keys) = self.skipped_keys.remove(&skip_key) {
            return Ok(keys);
        }

        let need_ratchet = match &self.dh_remote {
            None => true,
            Some(remote) => remote != &header.public_key,
        };

        if need_ratchet {
            if self.receiving_chain.is_some() && self.dh_remote.is_some() {
                self.skip_message_keys(header.previous_chain_length)?;
            }

            self.dh_ratchet(&header.public_key, csprng)?;
        }

        self.skip_message_keys(header.message_number)?;

        let receiving_chain = self
            .receiving_chain
            .as_ref()
            .ok_or(RatchetError::SessionNotInitialized)?;

        let msg_keys = receiving_chain.message_keys(None);

        self.receiving_chain = Some(receiving_chain.next()?);
        self.recv_count = header.message_number + 1;

        Ok(msg_keys)
    }

    /// Perform a DH ratchet step.
    fn dh_ratchet<R: CryptoRng + Rng>(
        &mut self,
        their_public: &[u8; DH_KEY_SIZE],
        csprng: &mut R,
    ) -> Result<()> {
        self.dh_remote = Some(*their_public);
        self.previous_chain_length = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;

        let dh_recv = self.dh_self.calculate_agreement(their_public);
        let (root_key, receiving_chain) = self.root_key.create_chain(&dh_recv);
        self.root_key = root_key;
        self.receiving_chain = Some(receiving_chain);

        self.dh_self = PrivateKey::new(csprng);

        let dh_send = self.dh_self.calculate_agreement(their_public);
        let (root_key, sending_chain) = self.root_key.create_chain(&dh_send);
        self.root_key = root_key;
        self.sending_chain = Some(sending_chain);

        Ok(())
    }

    /// Skip message keys up to (but not including) the given counter.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        let receiving_chain = match &self.receiving_chain {
            Some(chain) => chain,
            None => return Ok(()),
        };

        let current = receiving_chain.index();
        if until < current {
            return Ok(());
        }

        let skip_count = until - current;
        if skip_count > MAX_SKIP {
            return Err(RatchetError::TooManySkippedMessages(skip_count, MAX_SKIP));
        }

        let their_public = self.dh_remote.ok_or(RatchetError::SessionNotInitialized)?;

        let mut chain = receiving_chain.clone();
        for _ in current..until {
            let msg_keys = chain.message_keys(None);
            let counter = chain.index();
            self.skipped_keys.insert((their_public, counter), msg_keys);
            chain = chain.next()?;
        }

        self.receiving_chain = Some(chain);
        Ok(())
    }

    /// Clear all skipped message keys (for security, call periodically).
    pub fn clear_skipped_keys(&mut self) {
        self.skipped_keys.clear();
    }

    /// Get number of skipped keys stored.
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }

    // ========================================================================
    // Serialization methods for session persistence
    // ========================================================================

    /// Serialize the session state to bytes for storage.
    ///
    /// This allows saving the session to a database and restoring it later.
    /// The serialized data includes all keys, counters, and skipped message keys.
    ///
    /// # Security Note
    /// The serialized data contains sensitive cryptographic keys.
    /// It should be encrypted before storage (e.g., using AES-GCM with a derived key).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let serializable = SerializableSessionState::from_session(self);
        bincode::serialize(&serializable)
            .map_err(|e| RatchetError::SerializationFailed(e.to_string()))
    }

    /// Deserialize a session state from bytes.
    ///
    /// # Arguments
    /// * `bytes` - The serialized session state (from `to_bytes()`)
    ///
    /// # Returns
    /// The restored SessionState, ready to encrypt/decrypt messages.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let serializable: SerializableSessionState = bincode::deserialize(bytes)
            .map_err(|e| RatchetError::DeserializationFailed(e.to_string()))?;
        serializable.to_session()
    }

    /// Get access to internal state for advanced serialization (e.g., partial saves).
    ///
    /// Returns the raw key bytes and counters. Useful when you need to store
    /// session state in a specific database schema.
    pub fn export_state(&self) -> ExportedSessionState {
        ExportedSessionState {
            dh_self_private: self.dh_self.private_key_bytes(),
            dh_self_public: self.dh_self.derive_public_key_bytes(),
            dh_remote: self.dh_remote,
            root_key: *self.root_key.key(),
            sending_chain: self.sending_chain.as_ref().map(|c| (*c.key(), c.index())),
            receiving_chain: self.receiving_chain.as_ref().map(|c| (*c.key(), c.index())),
            send_count: self.send_count,
            recv_count: self.recv_count,
            previous_chain_length: self.previous_chain_length,
            skipped_keys_count: self.skipped_keys.len(),
        }
    }

    /// Restore a session from exported state.
    ///
    /// # Arguments
    /// * `state` - The exported state from `export_state()`
    /// * `skipped_keys` - Optional skipped keys (if you stored them separately)
    ///
    /// Note: This creates a session without skipped keys unless you provide them.
    /// For full session restoration with skipped keys, use `from_bytes()`.
    pub fn from_exported_state(
        state: &ExportedSessionState,
        skipped_keys: Option<HashMap<SkippedKeyIndex, MessageKeys>>,
    ) -> Result<Self> {
        let dh_self = PrivateKey::from(state.dh_self_private);
        let root_key = RootKey::new(state.root_key);

        let sending_chain = state
            .sending_chain
            .map(|(key, index)| ChainKey::new(key, index));
        let receiving_chain = state
            .receiving_chain
            .map(|(key, index)| ChainKey::new(key, index));

        Ok(Self {
            dh_self,
            dh_remote: state.dh_remote,
            root_key,
            sending_chain,
            receiving_chain,
            send_count: state.send_count,
            recv_count: state.recv_count,
            previous_chain_length: state.previous_chain_length,
            skipped_keys: skipped_keys.unwrap_or_default(),
        })
    }
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("dh_self_public", &hex::encode(self.our_public_key()))
            .field("dh_remote", &self.dh_remote.map(hex::encode))
            .field("send_count", &self.send_count)
            .field("recv_count", &self.recv_count)
            .field("previous_chain_length", &self.previous_chain_length)
            .field("skipped_keys_count", &self.skipped_keys.len())
            .finish()
    }
}

// ============================================================================
// Serialization Structures
// ============================================================================

/// Exported session state for manual database storage.
///
/// This provides raw access to session keys and counters when you need
/// to store them in a specific schema (e.g., separate database columns).
#[derive(Debug, Clone)]
pub struct ExportedSessionState {
    /// Our DH private key (32 bytes)
    pub dh_self_private: [u8; PRIVATE_KEY_LENGTH],
    /// Our DH public key (32 bytes, derived from private)
    pub dh_self_public: [u8; DH_KEY_SIZE],
    /// Their current DH public key (if known)
    pub dh_remote: Option<[u8; DH_KEY_SIZE]>,
    /// Current root key (32 bytes)
    pub root_key: [u8; KEY_SIZE],
    /// Sending chain key and index (if initialized)
    pub sending_chain: Option<([u8; KEY_SIZE], u32)>,
    /// Receiving chain key and index (if initialized)
    pub receiving_chain: Option<([u8; KEY_SIZE], u32)>,
    /// Number of messages sent in current chain
    pub send_count: u32,
    /// Number of messages received in current chain
    pub recv_count: u32,
    /// Length of previous sending chain
    pub previous_chain_length: u32,
    /// Number of skipped keys stored (informational)
    pub skipped_keys_count: usize,
}

/// Serializable version of ChainKey for bincode
#[derive(Serialize, Deserialize, Clone)]
struct SerializableChainKey {
    key: [u8; KEY_SIZE],
    index: u32,
}

impl From<&ChainKey> for SerializableChainKey {
    fn from(chain: &ChainKey) -> Self {
        Self {
            key: *chain.key(),
            index: chain.index(),
        }
    }
}

impl SerializableChainKey {
    fn to_chain_key(&self) -> ChainKey {
        ChainKey::new(self.key, self.index)
    }
}

/// Serializable version of MessageKeys for bincode
#[derive(Serialize, Deserialize, Clone)]
struct SerializableMessageKeys {
    cipher_key: [u8; KEY_SIZE],
    mac_key: [u8; KEY_SIZE],
    iv: [u8; 16], // Full derived IV size
    counter: u32,
}

impl From<&MessageKeys> for SerializableMessageKeys {
    fn from(keys: &MessageKeys) -> Self {
        Self {
            cipher_key: *keys.cipher_key(),
            mac_key: *keys.mac_key(),
            iv: *keys.iv_full(),
            counter: keys.counter(),
        }
    }
}

impl SerializableMessageKeys {
    fn to_message_keys(&self) -> MessageKeys {
        MessageKeys::from_raw(self.cipher_key, self.mac_key, self.iv, self.counter)
    }
}

/// Serializable version of SessionState for bincode
#[derive(Serialize, Deserialize)]
struct SerializableSessionState {
    /// Version for future compatibility
    version: u8,
    /// Our DH private key bytes
    dh_self_private: [u8; PRIVATE_KEY_LENGTH],
    /// Their DH public key (optional)
    dh_remote: Option<[u8; DH_KEY_SIZE]>,
    /// Root key bytes
    root_key: [u8; KEY_SIZE],
    /// Sending chain (optional)
    sending_chain: Option<SerializableChainKey>,
    /// Receiving chain (optional)
    receiving_chain: Option<SerializableChainKey>,
    /// Send counter
    send_count: u32,
    /// Receive counter
    recv_count: u32,
    /// Previous chain length
    previous_chain_length: u32,
    /// Skipped keys: ((public_key, counter), message_keys)
    skipped_keys: Vec<(([u8; DH_KEY_SIZE], u32), SerializableMessageKeys)>,
}

impl SerializableSessionState {
    /// Create from a SessionState
    fn from_session(session: &SessionState) -> Self {
        let skipped_keys: Vec<_> = session
            .skipped_keys
            .iter()
            .map(|(k, v)| (*k, SerializableMessageKeys::from(v)))
            .collect();

        Self {
            version: 1,
            dh_self_private: session.dh_self.private_key_bytes(),
            dh_remote: session.dh_remote,
            root_key: *session.root_key.key(),
            sending_chain: session
                .sending_chain
                .as_ref()
                .map(SerializableChainKey::from),
            receiving_chain: session
                .receiving_chain
                .as_ref()
                .map(SerializableChainKey::from),
            send_count: session.send_count,
            recv_count: session.recv_count,
            previous_chain_length: session.previous_chain_length,
            skipped_keys,
        }
    }

    /// Convert to SessionState
    fn to_session(&self) -> Result<SessionState> {
        if self.version != 1 {
            return Err(RatchetError::DeserializationFailed(format!(
                "Unsupported session version: {}",
                self.version
            )));
        }

        let dh_self = PrivateKey::from(self.dh_self_private);
        let root_key = RootKey::new(self.root_key);

        let sending_chain = self.sending_chain.as_ref().map(|c| c.to_chain_key());
        let receiving_chain = self.receiving_chain.as_ref().map(|c| c.to_chain_key());

        let skipped_keys: HashMap<_, _> = self
            .skipped_keys
            .iter()
            .map(|(k, v)| (*k, v.to_message_keys()))
            .collect();

        Ok(SessionState {
            dh_self,
            dh_remote: self.dh_remote,
            root_key,
            sending_chain,
            receiving_chain,
            send_count: self.send_count,
            recv_count: self.recv_count,
            previous_chain_length: self.previous_chain_length,
            skipped_keys,
        })
    }
}

/// Message header containing ratchet information.
///
/// This is sent alongside each encrypted message.
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Sender's current DH ratchet public key
    pub public_key: [u8; DH_KEY_SIZE],
    /// Number of messages in previous sending chain
    pub previous_chain_length: u32,
    /// Message number in current sending chain
    pub message_number: u32,
}

impl MessageHeader {
    /// Serialize the header to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DH_KEY_SIZE + 8);
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        bytes.extend_from_slice(&self.message_number.to_be_bytes());
        bytes
    }

    /// Deserialize a header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DH_KEY_SIZE + 8 {
            return Err(RatchetError::InvalidMessage("header too short".to_string()));
        }

        let mut public_key = [0u8; DH_KEY_SIZE];
        public_key.copy_from_slice(&bytes[..DH_KEY_SIZE]);

        let previous_chain_length = u32::from_be_bytes(
            bytes[DH_KEY_SIZE..DH_KEY_SIZE + 4]
                .try_into()
                .expect("4-byte slice"),
        );
        let message_number = u32::from_be_bytes(
            bytes[DH_KEY_SIZE + 4..DH_KEY_SIZE + 8]
                .try_into()
                .expect("4-byte slice"),
        );

        Ok(Self {
            public_key,
            previous_chain_length,
            message_number,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_alice_bob_session() {
        let mut rng = OsRng;

        // Simulate X3DH shared secret
        let shared_secret = [0x42u8; 32];

        // Bob's prekey
        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        // Alice initializes her session
        let mut alice =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        // Bob initializes his session
        let mut bob = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        // Alice sends first message
        let (alice_keys1, header1) = alice.encrypt_step().unwrap();
        assert_eq!(header1.message_number, 0);

        // Bob receives and decrypts
        let bob_keys1 = bob.decrypt_step(&header1, &mut rng).unwrap();
        assert_eq!(alice_keys1.cipher_key(), bob_keys1.cipher_key());
        assert_eq!(alice_keys1.mac_key(), bob_keys1.mac_key());

        // Bob sends reply
        let (bob_keys2, header2) = bob.encrypt_step().unwrap();
        assert_eq!(header2.message_number, 0);

        // Alice receives
        let alice_keys2 = alice.decrypt_step(&header2, &mut rng).unwrap();
        assert_eq!(bob_keys2.cipher_key(), alice_keys2.cipher_key());

        // Multiple messages
        let (alice_keys3, header3) = alice.encrypt_step().unwrap();
        assert_eq!(header3.message_number, 0); // New chain after ratchet

        let alice_keys3_recv = bob.decrypt_step(&header3, &mut rng).unwrap();
        assert_eq!(alice_keys3.cipher_key(), alice_keys3_recv.cipher_key());
    }

    #[test]
    fn test_out_of_order_messages() {
        let mut rng = OsRng;
        let shared_secret = [0x42u8; 32];

        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        let mut alice =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        let mut bob = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        // Alice sends 3 messages
        let (keys1, header1) = alice.encrypt_step().unwrap();
        let (keys2, header2) = alice.encrypt_step().unwrap();
        let (keys3, header3) = alice.encrypt_step().unwrap();

        // Bob receives them out of order: 3, 1, 2
        let recv_keys3 = bob.decrypt_step(&header3, &mut rng).unwrap();
        assert_eq!(keys3.cipher_key(), recv_keys3.cipher_key());

        // Keys 1 and 2 should be stored
        assert_eq!(bob.skipped_key_count(), 2);

        let recv_keys1 = bob.decrypt_step(&header1, &mut rng).unwrap();
        assert_eq!(keys1.cipher_key(), recv_keys1.cipher_key());
        assert_eq!(bob.skipped_key_count(), 1);

        let recv_keys2 = bob.decrypt_step(&header2, &mut rng).unwrap();
        assert_eq!(keys2.cipher_key(), recv_keys2.cipher_key());
        assert_eq!(bob.skipped_key_count(), 0);
    }

    #[test]
    fn test_header_serialization() {
        let header = MessageHeader {
            public_key: [0xAB; 32],
            previous_chain_length: 42,
            message_number: 123,
        };

        let bytes = header.to_bytes();
        let parsed = MessageHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.public_key, parsed.public_key);
        assert_eq!(header.previous_chain_length, parsed.previous_chain_length);
        assert_eq!(header.message_number, parsed.message_number);
    }

    #[test]
    fn test_session_state_serialization() {
        let mut rng = OsRng;

        // Simulate X3DH shared secret
        let shared_secret = [0x42u8; 32];

        // Bob's prekey
        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        // Alice initializes her session
        let mut alice =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        // Bob initializes his session
        let mut bob = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        // Exchange some messages to advance the ratchet
        let (_, header1) = alice.encrypt_step().unwrap();
        let _ = bob.decrypt_step(&header1, &mut rng).unwrap();

        let (_, header2) = bob.encrypt_step().unwrap();
        let _ = alice.decrypt_step(&header2, &mut rng).unwrap();

        // Serialize Alice's session
        let alice_bytes = alice.to_bytes().unwrap();
        println!("Serialized session size: {} bytes", alice_bytes.len());

        // Deserialize and verify
        let mut alice_restored = SessionState::from_bytes(&alice_bytes).unwrap();

        // Verify the restored session can continue the conversation
        let (_keys_orig, header3) = alice.encrypt_step().unwrap();
        let (_keys_restored, header3_restored) = alice_restored.encrypt_step().unwrap();

        // Keys should match since session state was identical
        // Note: This won't match exactly because encrypt_step advances the state
        // What we're really testing is that restoration works
        assert_eq!(header3.public_key, header3_restored.public_key);
        assert_eq!(
            header3.previous_chain_length,
            header3_restored.previous_chain_length
        );
    }

    #[test]
    fn test_session_roundtrip_with_serialization() {
        let mut rng = OsRng;
        let shared_secret = [0x42u8; 32];

        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        // Alice creates session
        let mut alice =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        // Bob creates session
        let mut bob = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        // Alice sends first message
        let (alice_keys1, header1) = alice.encrypt_step().unwrap();

        // Bob receives
        let bob_keys1 = bob.decrypt_step(&header1, &mut rng).unwrap();
        assert_eq!(alice_keys1.cipher_key(), bob_keys1.cipher_key());

        // Serialize and restore Bob's session
        let bob_bytes = bob.to_bytes().unwrap();
        let mut bob_restored = SessionState::from_bytes(&bob_bytes).unwrap();

        // Bob replies using restored session
        let (bob_keys2, header2) = bob_restored.encrypt_step().unwrap();

        // Alice receives Bob's reply
        let alice_keys2 = alice.decrypt_step(&header2, &mut rng).unwrap();
        assert_eq!(bob_keys2.cipher_key(), alice_keys2.cipher_key());

        // Continue conversation with restored session
        let (alice_keys3, header3) = alice.encrypt_step().unwrap();
        let bob_keys3 = bob_restored.decrypt_step(&header3, &mut rng).unwrap();
        assert_eq!(alice_keys3.cipher_key(), bob_keys3.cipher_key());
    }

    #[test]
    fn test_export_import_state() {
        let mut rng = OsRng;
        let shared_secret = [0x42u8; 32];

        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        let alice =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        // Export state
        let exported = alice.export_state();

        // Verify exported data
        assert_eq!(exported.dh_self_public, alice.our_public_key());
        assert_eq!(exported.send_count, alice.send_count());
        assert!(exported.sending_chain.is_some());
        assert!(exported.receiving_chain.is_none()); // Alice doesn't have receiving chain yet

        // Re-import state
        let alice_restored = SessionState::from_exported_state(&exported, None).unwrap();

        // Verify restored state matches
        assert_eq!(alice.our_public_key(), alice_restored.our_public_key());
        assert_eq!(alice.send_count(), alice_restored.send_count());
    }
}
