//
// Zenth Double Ratchet Protocol - Constants
//

use std::time::Duration;

/// Maximum number of message keys to skip when receiving out-of-order messages.
/// This prevents an attacker from causing unbounded memory growth.
pub const MAX_SKIP: u32 = 1000;

/// Maximum number of messages that can be sent in a single chain before
/// requiring a DH ratchet step (recommended by Signal spec).
pub const MAX_CHAIN_LENGTH: u32 = 1000;

/// Maximum number of receiver chains to keep (for multiple ratchet steps).
pub const MAX_RECEIVER_CHAINS: usize = 5;

/// Size of symmetric keys (AES-256)
pub const KEY_SIZE: usize = 32;

/// Size of public/private keys (X25519)
pub const DH_KEY_SIZE: usize = 32;

/// Size of MAC keys
pub const MAC_KEY_SIZE: usize = 32;

/// Size of initialization vectors for AES-GCM (12 bytes standard)
pub const IV_SIZE: usize = 12;

/// Size of authentication tags for AES-GCM
pub const TAG_SIZE: usize = 16;

/// HKDF info string for root key ratcheting (Signal compatible)
pub const KDF_RK_INFO: &[u8] = b"WhisperRatchet";

/// HKDF info string for message key derivation (Signal compatible)
pub const KDF_MESSAGE_INFO: &[u8] = b"WhisperMessageKeys";

/// HKDF info string for initial session derivation
pub const KDF_SESSION_INFO: &[u8] = b"ZenthSession";

/// Chain key seed for deriving message keys (Signal spec: 0x01)
pub const MESSAGE_KEY_SEED: [u8; 1] = [0x01];

/// Chain key seed for deriving next chain key (Signal spec: 0x02)
pub const CHAIN_KEY_SEED: [u8; 1] = [0x02];

/// Maximum age of unacknowledged session before soft archiving (30 days)
pub const MAX_UNACKNOWLEDGED_SESSION_AGE: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;
