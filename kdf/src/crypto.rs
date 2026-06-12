//
// Cryptographic primitives for Double Ratchet protocol
//

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Computes HMAC-SHA256 over `input` using `key` and returns the 32-byte tag.
///
/// Used by the Double Ratchet chain key step to derive message keys and
/// advance the chain key (seed bytes `0x01` and `0x02` respectively).
/// HMAC-SHA256 accepts keys of any length.
#[inline]
pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(input);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_basic() {
        let key = b"secret key";
        let data = b"hello world";

        let result = hmac_sha256(key, data);
        assert_eq!(result.len(), 32);

        // Same inputs should produce same output
        let result2 = hmac_sha256(key, data);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_hmac_sha256_chain_key_seeds() {
        // Test with Signal's chain key seed constants
        let chain_key = [0x8a; 32];

        // MESSAGE_KEY_SEED = 0x01
        let message_seed = hmac_sha256(&chain_key, &[0x01]);
        assert_eq!(message_seed.len(), 32);

        // CHAIN_KEY_SEED = 0x02
        let next_chain = hmac_sha256(&chain_key, &[0x02]);
        assert_eq!(next_chain.len(), 32);

        // Should produce different outputs
        assert_ne!(message_seed, next_chain);
    }

    #[test]
    fn test_hmac_sha256_known_vector() {
        // RFC 4231 Test Case 1
        let key = [0x0b; 20];
        let data = b"Hi There";

        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];

        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }
}
