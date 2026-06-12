//! Double Ratchet message encryption and decryption.
//!
//! Wraps a [`SessionState`] and provides high-level AES-256-GCM encrypt/decrypt
//! operations, with the message header used as AEAD associated data.

use rand::{CryptoRng, Rng};

use aes_modes::{Aes256GcmDecryption, Aes256GcmEncryption};

use crate::consts::{PROTOCOL_VERSION, TAG_SIZE};
use crate::errors::{RatchetError, Result};
use crate::keys::MessageKeys;
use crate::state::{MessageHeader, SessionState};

/// An encrypted message with its header.
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    /// Protocol version
    pub version: u8,
    /// Message header (contains ratchet public key and counters)
    pub header: MessageHeader,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub tag: [u8; TAG_SIZE],
}

impl EncryptedMessage {
    /// Serialize the entire message to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let mut bytes =
            Vec::with_capacity(1 + header_bytes.len() + self.ciphertext.len() + TAG_SIZE);

        bytes.push(self.version);
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes.extend_from_slice(&self.tag);

        bytes
    }

    /// Deserialize a message from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 1 + 40 + 4 + TAG_SIZE {
            return Err(RatchetError::InvalidMessage(
                "message too short".to_string(),
            ));
        }

        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(RatchetError::InvalidMessage(format!(
                "unsupported protocol version: {}",
                version
            )));
        }

        let header = MessageHeader::from_bytes(&bytes[1..41])?;

        let ciphertext_len =
            u32::from_be_bytes(bytes[41..45].try_into().expect("4-byte slice")) as usize;

        if bytes.len() < 45 + ciphertext_len + TAG_SIZE {
            return Err(RatchetError::InvalidMessage(
                "ciphertext length mismatch".to_string(),
            ));
        }

        let ciphertext = bytes[45..45 + ciphertext_len].to_vec();

        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&bytes[45 + ciphertext_len..45 + ciphertext_len + TAG_SIZE]);

        Ok(Self {
            version,
            header,
            ciphertext,
            tag,
        })
    }
}

/// Session cipher for encrypting and decrypting messages.
///
/// Wraps a SessionState and provides high-level encrypt/decrypt operations.
pub struct SessionCipher {
    state: SessionState,
}

impl SessionCipher {
    /// Create a new session cipher from an initialized session state.
    pub fn new(state: SessionState) -> Self {
        Self { state }
    }

    /// Get a reference to the underlying session state.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Get a mutable reference to the underlying session state.
    pub fn state_mut(&mut self) -> &mut SessionState {
        &mut self.state
    }

    /// Consume the cipher and return the session state.
    pub fn into_state(self) -> SessionState {
        self.state
    }

    /// Encrypt a plaintext message.
    ///
    /// # Arguments
    /// * `plaintext` - The message to encrypt
    ///
    /// # Returns
    /// The encrypted message with header
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let (msg_keys, header) = self.state.encrypt_step()?;
        let (ciphertext, tag) = encrypt_with_keys(&msg_keys, &header, plaintext)?;

        Ok(EncryptedMessage {
            version: PROTOCOL_VERSION,
            header,
            ciphertext,
            tag,
        })
    }

    /// Decrypt an encrypted message.
    ///
    /// # Arguments
    /// * `message` - The encrypted message
    /// * `csprng` - RNG for ratchet operations
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt<R: CryptoRng + Rng>(
        &mut self,
        message: &EncryptedMessage,
        csprng: &mut R,
    ) -> Result<Vec<u8>> {
        if message.version != PROTOCOL_VERSION {
            return Err(RatchetError::InvalidMessage(format!(
                "unsupported protocol version: {}",
                message.version
            )));
        }

        let msg_keys = self.state.decrypt_step(&message.header, csprng)?;

        decrypt_with_keys(
            &msg_keys,
            &message.header,
            &message.ciphertext,
            &message.tag,
        )
    }
}

/// Encrypt plaintext using message keys.
fn encrypt_with_keys(
    keys: &MessageKeys,
    header: &MessageHeader,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_SIZE])> {
    let iv = keys.iv();
    let ad = header.to_bytes();

    let mut gcm = Aes256GcmEncryption::new(keys.cipher_key(), &iv, &ad)
        .map_err(|e| RatchetError::EncryptionFailed(format!("{:?}", e)))?;

    let mut ciphertext = plaintext.to_vec();
    gcm.encrypt(&mut ciphertext);

    let tag = gcm.compute_tag();

    Ok((ciphertext, tag))
}

/// Decrypt ciphertext using message keys.
fn decrypt_with_keys(
    keys: &MessageKeys,
    header: &MessageHeader,
    ciphertext: &[u8],
    tag: &[u8; TAG_SIZE],
) -> Result<Vec<u8>> {
    let iv = keys.iv();
    let ad = header.to_bytes();

    let mut gcm = Aes256GcmDecryption::new(keys.cipher_key(), &iv, &ad)
        .map_err(|e| RatchetError::DecryptionFailed(format!("{:?}", e)))?;

    let mut plaintext = ciphertext.to_vec();
    gcm.decrypt(&mut plaintext);

    gcm.verify_tag(tag).map_err(|_| RatchetError::InvalidTag)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use exchange::curve25519::PrivateKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = OsRng;
        let shared_secret = [0x42u8; 32];

        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        let alice_state =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        let bob_state = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        let mut alice = SessionCipher::new(alice_state);
        let mut bob = SessionCipher::new(bob_state);

        // Alice sends message
        let plaintext = b"Hello, Bob!";
        let encrypted = alice.encrypt(plaintext).unwrap();

        // Bob decrypts
        let decrypted = bob.decrypt(&encrypted, &mut rng).unwrap();
        assert_eq!(decrypted, plaintext);

        // Bob replies
        let reply = b"Hello, Alice!";
        let encrypted_reply = bob.encrypt(reply).unwrap();

        // Alice decrypts
        let decrypted_reply = alice.decrypt(&encrypted_reply, &mut rng).unwrap();
        assert_eq!(decrypted_reply, reply);
    }

    #[test]
    fn test_multiple_messages() {
        let mut rng = OsRng;
        let shared_secret = [0x42u8; 32];

        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        let alice_state =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        let bob_state = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        let mut alice = SessionCipher::new(alice_state);
        let mut bob = SessionCipher::new(bob_state);

        // Exchange multiple messages
        for i in 0..10 {
            let msg = format!("Message {} from Alice", i);
            let encrypted = alice.encrypt(msg.as_bytes()).unwrap();
            let decrypted = bob.decrypt(&encrypted, &mut rng).unwrap();
            assert_eq!(decrypted, msg.as_bytes());

            let reply = format!("Reply {} from Bob", i);
            let encrypted_reply = bob.encrypt(reply.as_bytes()).unwrap();
            let decrypted_reply = alice.decrypt(&encrypted_reply, &mut rng).unwrap();
            assert_eq!(decrypted_reply, reply.as_bytes());
        }
    }

    #[test]
    fn test_message_serialization() {
        let mut rng = OsRng;
        let shared_secret = [0x42u8; 32];

        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        let alice_state =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        let bob_state = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        let mut alice = SessionCipher::new(alice_state);
        let mut bob = SessionCipher::new(bob_state);

        let plaintext = b"Test serialization";
        let encrypted = alice.encrypt(plaintext).unwrap();

        // Serialize and deserialize
        let bytes = encrypted.to_bytes();
        let parsed = EncryptedMessage::from_bytes(&bytes).unwrap();

        // Decrypt the parsed message
        let decrypted = bob.decrypt(&parsed, &mut rng).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_message_fails() {
        let mut rng = OsRng;
        let shared_secret = [0x42u8; 32];

        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        let alice_state =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        let bob_state = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        let mut alice = SessionCipher::new(alice_state);
        let mut bob = SessionCipher::new(bob_state);

        let plaintext = b"Secret message";
        let mut encrypted = alice.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        // Should fail verification
        let result = bob.decrypt(&encrypted, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_out_of_order_delivery() {
        let mut rng = OsRng;
        let shared_secret = [0x42u8; 32];

        let bob_prekey = PrivateKey::new(&mut rng);
        let bob_prekey_public = bob_prekey.derive_public_key_bytes();

        let alice_state =
            SessionState::initialize_alice(&shared_secret, &bob_prekey_public, &mut rng).unwrap();

        let bob_state = SessionState::initialize_bob(&shared_secret, bob_prekey).unwrap();

        let mut alice = SessionCipher::new(alice_state);
        let mut bob = SessionCipher::new(bob_state);

        // Alice sends 3 messages
        let msg1 = alice.encrypt(b"Message 1").unwrap();
        let msg2 = alice.encrypt(b"Message 2").unwrap();
        let msg3 = alice.encrypt(b"Message 3").unwrap();

        // Bob receives them out of order
        let dec3 = bob.decrypt(&msg3, &mut rng).unwrap();
        assert_eq!(dec3, b"Message 3");

        let dec1 = bob.decrypt(&msg1, &mut rng).unwrap();
        assert_eq!(dec1, b"Message 1");

        let dec2 = bob.decrypt(&msg2, &mut rng).unwrap();
        assert_eq!(dec2, b"Message 2");
    }
}
