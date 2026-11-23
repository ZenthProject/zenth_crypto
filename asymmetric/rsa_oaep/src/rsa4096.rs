use encoding::base64::{EncodeImpl, EncodeSecure};
use rand::rngs::SysRng;
use rsa::sha2::Sha512;
use rsa::{PrivateKey, PublicKey};


/// RSA-4096 keypair for OAEP encryption and decryption.
///
/// Keys are generated at construction time using the OS CSPRNG ([`OsRng`]).
/// The private key is never exposed outside this struct; the public key is
/// used exclusively for encryption.
///
/// Ciphertexts are returned as Base64-encoded strings for convenient transport.
pub struct Rsa4096 {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl Default for Rsa4096 {
    fn default() -> Self {
        Self::new()
    }
}

impl Rsa4096 {

    /// Generates a fresh RSA-4096 keypair using the OS CSPRNG.
    ///
    /// Key generation at 4096 bits is computationally intensive and may take
    /// several seconds depending on the hardware.
    ///
    /// # Panics
    ///
    /// Panics if the OS fails to provide sufficient entropy for key generation.
    pub fn new() -> Self {
        let mut rng = SysRng;

        let private_key = PrivateKey::new(&mut rng, 4096)
            .expect("RSA-4096 key generation failed");

        let public_key = private_key.to_public_key();

        Self {
            private_key,
            public_key,
        }
    }

    /// Encrypts `message` with RSA-4096 OAEP (SHA-512) and returns a Base64 ciphertext.
    ///
    /// OAEP padding is probabilistic: encrypting the same plaintext twice produces
    /// different ciphertexts, providing semantic security.
    ///
    /// # Arguments
    ///
    /// * `message` — plaintext bytes to encrypt. Must be at most 446 bytes
    ///   (RSA-4096 with SHA-512 OAEP limit).
    ///
    /// # Panics
    ///
    /// Panics if encryption fails, which should not occur under normal conditions.
    pub fn encrypt(&self, message: &[u8]) -> String {
        let encrypted = self.public_key
            .oaep_encrypt::<Sha512>(message)
            .expect("RSA-OAEP encryption failed");

        EncodeImpl::base64encode(&encrypted)
    }

    /// Decrypts a Base64-encoded RSA-4096 OAEP ciphertext and returns the plaintext.
    ///
    /// # Arguments
    ///
    /// * `encrypted_string` — Base64-encoded ciphertext produced by [`Rsa4096::encrypt`].
    ///
    /// # Panics
    ///
    /// Panics if `encrypted_string` is not valid Base64, or if decryption fails
    /// (e.g. wrong key, corrupted ciphertext).
    pub fn decrypt(&self, encrypted_string: &str) -> Vec<u8> {
        let encrypted_bytes =
            EncodeImpl::base64_vecdecode(encrypted_string)
                .expect("Invalid Base64 ciphertext");

        self.private_key
            .oaep_decrypt::<Sha512>(&encrypted_bytes)
            .expect("RSA-OAEP decryption failed")
    }
}
