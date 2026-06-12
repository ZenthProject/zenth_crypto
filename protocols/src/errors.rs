//
// Zenth Double Ratchet Protocol - Error Types
//

use thiserror::Error;

/// Errors that can occur during Double Ratchet operations
#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("message counter overflow")]
    CounterOverflow,

    #[error("message too old: counter {message_counter} < session counter {session_counter}")]
    MessageTooOld {
        message_counter: u32,
        session_counter: u32,
    },

    #[error("too many skipped messages: {0} exceeds maximum {1}")]
    TooManySkippedMessages(u32, u32),

    #[error("duplicate message detected: counter {0}")]
    DuplicateMessage(u32),

    #[error("session not initialized")]
    SessionNotInitialized,

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("key agreement failed")]
    KeyAgreementFailed,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid tag")]
    InvalidTag,

    #[error("internal error: {0}")]
    InternalError(String),

    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
}

pub type Result<T> = std::result::Result<T, RatchetError>;
