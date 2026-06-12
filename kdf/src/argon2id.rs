//! Argon2id password hashing and key derivation.

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString, errors::InvalidValue,
    },
};
use rand::rngs::OsRng;

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
}
