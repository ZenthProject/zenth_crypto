use hashing::hash::CryptographicHash;
use pqcrypto_mldsa::mldsa44::PublicKey;
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;
use kdf::argon2id::Argon2idHasher;
use argon2::password_hash::SaltString;
use rand08::rngs::OsRng as OsRng08;

pub fn generate_public_key_hash(public_key_identitiy: &PublicKey) -> Result<String, String> {
    let mut hash = CryptographicHash::new("SHA256", 2)
        .map_err(|e| format!("Hash initialization error: {}", e))?;
    hash.update(public_key_identitiy.as_bytes());
    let hash_bytes: Vec<u8>  = hash.finalize();
    let hash_string: String = hash_bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();
    Ok(hash_string)
}

pub fn derive_keys_from_password(password: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let salt = SaltString::generate(&mut OsRng08);
    let salt_bytes = salt.as_str().as_bytes();
    let hash_password = match Argon2idHasher::new() {
        Ok(hasher) => hasher
            .derive_key(&password, salt_bytes, 32)
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }?;
    Ok((hash_password, salt_bytes.to_vec()))
}

/// Derive password hash using a specific salt (for login)
pub fn derive_keys_from_password_with_salt(password: &str, salt_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let hash_password = match Argon2idHasher::new() {
        Ok(hasher) => hasher
            .derive_key(&password, salt_bytes, 32)
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }?;
    Ok(hash_password)
}
