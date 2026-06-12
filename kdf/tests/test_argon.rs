use kdf::argon2id::Argon2idHasher;

// ============================================================================
// TESTS UNITAIRES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_hasher() {
        let result = Argon2idHasher::new();
        assert!(result.is_ok(), "Le hasher devrait se créer sans erreur");
    }

    #[test]
    fn test_hash_produces_valid_phc_string() {
        let hasher = Argon2idHasher::new().unwrap();
        let hash = hasher.hash("test_password").unwrap();

        assert!(hash.starts_with("$argon2id$"));
        assert!(hash.contains("$m=131072,t=6,p=4$"));
    }

    #[test]
    fn test_hash_generates_unique_salts() {
        let hasher = Argon2idHasher::new().unwrap();
        let hash1 = hasher.hash("same_password").unwrap();
        let hash2 = hasher.hash("same_password").unwrap();

        assert_ne!(hash1, hash2, "Les salts doivent être uniques");
    }

    #[test]
    fn test_verify_correct_password() {
        let hasher = Argon2idHasher::new().unwrap();
        let password = "correct_horse_battery_staple";
        let hash = hasher.hash(password).unwrap();

        let result = hasher.verify(password, &hash);
        assert!(result.is_ok(), "Le mot de passe correct doit être accepté");
    }

    #[test]
    fn test_verify_incorrect_password() {
        let hasher = Argon2idHasher::new().unwrap();
        let hash = hasher.hash("correct_password").unwrap();

        let result = hasher.verify("wrong_password", &hash);
        assert!(result.is_err(), "Un mauvais mot de passe doit être rejeté");
    }

    #[test]
    fn test_verify_invalid_hash_format() {
        let hasher = Argon2idHasher::new().unwrap();
        let result = hasher.verify("password", "invalid_hash_format");

        assert!(
            result.is_err(),
            "Un hash invalide doit retourner une erreur"
        );
    }

    #[test]
    fn test_derive_key_length() {
        let hasher = Argon2idHasher::new().unwrap();
        let salt = b"test_salt_16bytes";

        for len in [16, 32, 64] {
            let key = hasher.derive_key("password", salt, len).unwrap();
            assert_eq!(key.len(), len, "La clé doit avoir la longueur demandée");
        }
    }

    #[test]
    fn test_derive_key_deterministic() {
        let hasher = Argon2idHasher::new().unwrap();
        let password = "test_password";
        let salt = b"fixed_salt_for_app";

        let key1 = hasher.derive_key(password, salt, 32).unwrap();
        let key2 = hasher.derive_key(password, salt, 32).unwrap();

        assert_eq!(
            key1, key2,
            "Même password + salt doivent produire la même clé"
        );
    }

    #[test]
    fn test_derive_key_different_salts() {
        let hasher = Argon2idHasher::new().unwrap();
        let password = "same_password";

        let key1 = hasher.derive_key(password, b"salt_one", 32).unwrap();
        let key2 = hasher.derive_key(password, b"salt_two", 32).unwrap();

        assert_ne!(
            key1, key2,
            "Salts différents doivent produire clés différentes"
        );
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let hasher = Argon2idHasher::new().unwrap();
        let salt = b"same_salt_12345";

        let key1 = hasher.derive_key("password1", salt, 32).unwrap();
        let key2 = hasher.derive_key("password2", salt, 32).unwrap();

        assert_ne!(
            key1, key2,
            "Passwords différents doivent produire clés différentes"
        );
    }

    #[test]
    fn test_derive_key_salt_too_short() {
        let hasher = Argon2idHasher::new().unwrap();
        let short_salt = b"1234567";

        let result = hasher.derive_key("password", short_salt, 32);
        assert!(
            result.is_err(),
            "Un salt trop court doit retourner une erreur"
        );
    }

    #[test]
    fn test_derive_key_minimum_salt_length() {
        let hasher = Argon2idHasher::new().unwrap();
        let min_salt = b"12345678";

        let result = hasher.derive_key("password", min_salt, 32);
        assert!(result.is_ok(), "8 bytes de salt doivent être acceptés");
    }

    #[test]
    fn test_empty_password_handling() {
        let hasher = Argon2idHasher::new().unwrap();

        let hash = hasher.hash("").unwrap();
        assert!(hasher.verify("", &hash).is_ok());
        assert!(hasher.verify("not_empty", &hash).is_err());
    }

    #[test]
    fn test_long_password_handling() {
        let hasher = Argon2idHasher::new().unwrap();
        let long_password = "a".repeat(1000);

        let hash = hasher.hash(&long_password).unwrap();
        assert!(hasher.verify(&long_password, &hash).is_ok());
    }

    #[test]
    fn test_unicode_password() {
        let hasher = Argon2idHasher::new().unwrap();
        let unicode_pwd = "🔐 Mot de passe avec émojis et accènts 日本語";

        let hash = hasher.hash(unicode_pwd).unwrap();
        assert!(hasher.verify(unicode_pwd, &hash).is_ok());
    }

    #[test]
    fn test_derive_key_aes256_use_case() {
        let hasher = Argon2idHasher::new().unwrap();
        let user_password = "user_master_password";
        let app_context_salt = b"myapp_database_encryption_v1_salt";
        let aes_key = hasher
            .derive_key(user_password, app_context_salt, 32)
            .unwrap();
        assert_eq!(aes_key.len(), 32, "Clé AES-256 doit faire 32 bytes");
        let aes_key_again = hasher
            .derive_key(user_password, app_context_salt, 32)
            .unwrap();
        assert_eq!(aes_key, aes_key_again);
    }
}

// ============================================================================
// EXEMPLES D'UTILISATION
// ============================================================================

#[cfg(test)]
mod usage_examples {
    use super::*;

    #[test]
    fn example_password_storage_and_verification() {
        let hasher = Argon2idHasher::new().unwrap();
        let user_password = "Super$ecure123!";
        let password_hash = hasher.hash(user_password).unwrap();
        println!("Hash stocké en BDD : {}", password_hash);
        let login_attempt = "Super$ecure123!";
        match hasher.verify(login_attempt, &password_hash) {
            Ok(()) => println!("Utilisateur authentifié"),
            Err(_) => println!("Mot de passe incorrect"),
        }
    }

    // Example of deriving a key for file encryption
    // This is a common use case where you need to derive a key from a user password
    #[test]
    fn example_file_encryption_with_derived_key() {
        let hasher = Argon2idHasher::new().unwrap();

        let app_salt = b"myapp_file_crypto_v2";
        let user_password = "mon_mot_de_passe_secret";
        let encryption_key = hasher.derive_key(user_password, app_salt, 32).unwrap();
        println!(
            "Clé de chiffrement (hex) : {}",
            hex::encode(&encryption_key)
        );
        let decryption_key = hasher.derive_key(user_password, app_salt, 32).unwrap();
        assert_eq!(encryption_key, decryption_key, "Même clé si même password");
    }

    // Example of deriving multiple keys from the same master password
    // This is useful for applications that need different keys for different purposes
    // e.g. encryption key, HMAC key, backup key, etc.
    #[test]
    fn example_multi_key_derivation() {
        let hasher = Argon2idHasher::new().unwrap();
        let master_password = "master_password_123";

        let encryption_key = hasher
            .derive_key(master_password, b"app_encryption_salt", 32)
            .unwrap();

        let hmac_key = hasher
            .derive_key(master_password, b"app_hmac_salt______", 64)
            .unwrap();

        let backup_key = hasher
            .derive_key(master_password, b"app_backup_salt____", 32)
            .unwrap();

        println!("Clé chiffrement : {} bytes", encryption_key.len());
        println!("Clé HMAC        : {} bytes", hmac_key.len());
        println!("Clé backup      : {} bytes", backup_key.len());

        assert_ne!(encryption_key, backup_key);
    }
}

#[cfg(test)]
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
