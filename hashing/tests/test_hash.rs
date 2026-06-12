use encoding::base64::{EncodeImpl, EncodeSecure};
use hashing::hash::CryptographicHash;
use kdf::argon2id::Argon2idHasher;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        let data = b"test";
        let mut hasher = CryptographicHash::new("SHA-1", 1).unwrap();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let hash_b64 = EncodeImpl::base64encode(&hash_bytes);
        assert!(!hash_b64.is_empty());
        assert_ne!(hash_b64, EncodeImpl::base64encode(data));
    }

    #[test]
    fn test_sha256() {
        let data = b"test";
        let mut hasher = CryptographicHash::new("SHA-256", 1).unwrap();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let hash_b64 = EncodeImpl::base64encode(&hash_bytes);
        assert!(!hash_b64.is_empty());
        assert_ne!(hash_b64, EncodeImpl::base64encode(data));
    }

    #[test]
    fn test_sha512() {
        let data = b"test";
        let mut hasher = CryptographicHash::new("SHA-512", 1).unwrap();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let hash_b64 = EncodeImpl::base64encode(&hash_bytes);
        assert!(!hash_b64.is_empty());
        assert_ne!(hash_b64, EncodeImpl::base64encode(data));
    }

    #[test]
    fn test_sha512_multiple_rounds() {
        let data = b"test";
        let mut h1 = CryptographicHash::new("SHA-512", 1).unwrap();
        let mut h2 = CryptographicHash::new("SHA-512", 3).unwrap();
        h1.update(data);
        h2.update(data);
        let hash1 = EncodeImpl::base64encode(&h1.finalize());
        let hash2 = EncodeImpl::base64encode(&h2.finalize());
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_sha3_512() {
        let data = b"test";
        let mut hasher = CryptographicHash::new("SHA3-512", 1).unwrap();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let hash_b64 = EncodeImpl::base64encode(&hash_bytes);
        assert!(!hash_b64.is_empty());
    }

    #[test]
    fn test_keccak512() {
        let data = b"test";
        let mut hasher = CryptographicHash::new("KECCAK512", 1).unwrap();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let hash_b64 = EncodeImpl::base64encode(&hash_bytes);
        assert!(!hash_b64.is_empty());
    }

    #[test]
    fn test_md5() {
        let data = b"test";
        let mut hasher = CryptographicHash::new("MD5", 1).unwrap();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let hash_b64 = EncodeImpl::base64encode(&hash_bytes);
        assert!(!hash_b64.is_empty());
    }

    #[test]
    fn test_crc32() {
        let data = b"test";
        let mut hasher = CryptographicHash::new("CRC32", 1).unwrap();
        hasher.update(data);
        let hash_bytes = hasher.finalize();
        let hash_b64 = EncodeImpl::base64encode(&hash_bytes);
        assert!(!hash_b64.is_empty());
    }

    #[test]
    fn test_unicode_input() {
        let data = "🐍🚀🦀".as_bytes();
        let mut sha = CryptographicHash::new("SHA-512", 1).unwrap();
        let mut keccak = CryptographicHash::new("KECCAK512", 1).unwrap();
        let mut md5 = CryptographicHash::new("MD5", 1).unwrap();
        let mut crc = CryptographicHash::new("CRC32", 1).unwrap();
        sha.update(data);
        keccak.update(data);
        md5.update(data);
        crc.update(data);
        assert!(!EncodeImpl::base64encode(&sha.finalize()).is_empty());
        assert!(!EncodeImpl::base64encode(&keccak.finalize()).is_empty());
        assert!(!EncodeImpl::base64encode(&md5.finalize()).is_empty());
        assert!(!EncodeImpl::base64encode(&crc.finalize()).is_empty());
    }

    #[test]
    fn test_repeatability() {
        let data = b"repeat";
        let mut h1 = CryptographicHash::new("SHA-256", 2).unwrap();
        let mut h2 = CryptographicHash::new("SHA-256", 2).unwrap();
        h1.update(data);
        h2.update(data);
        let hash1 = h1.finalize();
        let hash2 = h2.finalize();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_valid_password_verification() {
        let hasher = Argon2idHasher::new().unwrap();
        let password = "secure_password";

        let hash = hasher.hash(password).unwrap();
        let result = hasher.verify(password, &hash);

        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_password_verification() {
        let hasher = Argon2idHasher::new().unwrap();
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let hash = hasher.hash(password).unwrap();
        let result = hasher.verify(wrong_password, &hash);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hash_format() {
        let hasher = Argon2idHasher::new().expect("Failed to create hasher");
        let password = "any_password";
        let bad_hash = "not-a-valid-hash";

        let result = hasher.verify(password, bad_hash);
        assert!(result.is_err(), "Invalid hash format should return error");
    }

    #[test]
    fn test_different_hashes_for_same_password() {
        let hasher = Argon2idHasher::new().expect("Failed to create hasher");
        let password = "reused_password";

        let hash1 = hasher.hash(password).expect("First hash failed");
        let hash2 = hasher.hash(password).expect("Second hash failed");

        assert_ne!(hash1, hash2, "Hashes should differ due to random salt");
    }
}
