//! Argon2id password hashing and key derivation.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString, errors::InvalidValue,
    },
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Argon2Error {
    #[error("invalid Argon2 parameters: {0}")]
    Params(String),

    #[error("salt too short: minimum 8 bytes required, got {0}")]
    SaltTooShort(usize),

    #[error("key derivation failed: {0}")]
    Derivation(String),

    #[error("hashing failed: {0}")]
    Hash(String),

    #[error("password verification failed: {0}")]
    Verify(String),
}


const KEY_SIZE: usize = 32;
const ARGON2_M_COST: u32 = 65_536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// Argon2id hasher pre-configured with OWASP-recommended parameters.
pub struct Argon2idHasher {
    argon2: Argon2<'static>,
}

impl Argon2idHasher {
    /// Constructs an [`Argon2idHasher`] with OWASP-recommended parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the hardcoded parameter values are rejected by the
    /// underlying `argon2` library (should not occur in practice).
    pub fn new() -> Result<Self, argon2::password_hash::Error> {
        let params = Params::new(131_072, 6, 4, None)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        Ok(Self { argon2 })
    }

    /// Hashes `password` with a randomly generated salt and returns the PHC string.
    ///
    /// The returned string is self-contained (includes algorithm, parameters, salt,
    /// and hash) and can be stored directly in a database for later verification.
    ///
    /// # Errors
    ///
    /// Returns an error if hashing fails.
    pub fn hash(&self, password: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(hash.to_string())
    }

    /// Verifies `password` against a PHC-format `hashed` string produced by [`hash`][Self::hash].
    ///
    /// # Errors
    ///
    /// Returns an error if `hashed` is malformed or if the password does not match.
    pub fn verify(&self, password: &str, hashed: &str) -> Result<(), argon2::password_hash::Error> {
        let parsed_hash = PasswordHash::new(hashed)?;
        self.argon2
            .verify_password(password.as_bytes(), &parsed_hash)
    }

    /// Derives a cryptographic key of `output_len` bytes from `password` and `salt`.
    ///
    /// Unlike [`hash`][Self::hash], this method does not generate a salt internally —
    /// the caller must supply a fixed, application-specific salt of at least 8 bytes.
    ///
    /// # Arguments
    ///
    /// * `password`   — the user-supplied password.
    /// * `salt`       — a fixed context-specific salt; must be at least 8 bytes.
    /// * `output_len` — desired key length in bytes (e.g. 16, 32, 64).
    ///
    /// # Errors
    ///
    /// Returns [`argon2::password_hash::Error::SaltInvalid`] if `salt` is shorter than
    /// 8 bytes, or an error from the underlying Argon2 implementation otherwise.
    pub fn derive_key(
        &self,
        password: &str,
        salt: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, argon2::password_hash::Error> {
        if salt.len() < 8 {
            return Err(argon2::password_hash::Error::SaltInvalid(
                InvalidValue::TooShort,
            ));
        }
        let mut key = vec![0u8; output_len];
        self.argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)?;
        Ok(key)
    }

    /// Dérive une clé SQLCipher à partir du mot de passe et du salt.
    ///
    /// Utilise Argon2id avec des paramètres sécurisés (64 MB, 3 itérations, 4 threads).
    ///
    /// # Errors
    ///
    /// Retourne une erreur si le salt est trop court ou si la dérivation échoue.
    pub fn derive_sqlcipher_key(
        password: &str,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_SIZE]>, Argon2Error> {
        if salt.len() < 8 {
            return Err(Argon2Error::SaltTooShort(salt.len()));
        }

        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
            .map_err(|e| Argon2Error::Params(format!("Argon2 params error: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        argon2
            .hash_password_into(password.as_bytes(), salt, key.as_mut())
            .map_err(|e| Argon2Error::Params(format!("Argon2 hash error: {}", e)))?;

        Ok(key)
    }

}
