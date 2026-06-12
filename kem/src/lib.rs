//! Post-quantum Key Encapsulation Mechanisms (KEM).
//!
//! Provides a unified API over three lattice-based KEM variants:
//!
//! | Variant        | NIST level | Public key | Ciphertext | Shared secret |
//! |----------------|------------|------------|------------|---------------|
//! | Kyber768       | 3          | 1 184 B    | 1 088 B    | 32 B          |
//! | Kyber1024      | 5          | 1 568 B    | 1 568 B    | 32 B          |
//! | ML-KEM 1024    | 5          | 1 568 B    | 1 568 B    | 32 B          |
//!
//! All secret keys are zeroed on drop via [`zeroize`].

use rand::CryptoRng;
use std::fmt;
use zeroize::Zeroize;

pub use rand as kem_rand;

pub mod kyber1024;
pub mod kyber768;
pub mod mlkem1024;

/// Identifies the KEM algorithm variant used by a keypair.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyType {
    /// Kyber768 — NIST security level 3, compact key sizes.
    Kyber768,
    /// Kyber1024 — NIST security level 5, maximum security.
    Kyber1024,
    /// ML-KEM 1024 — NIST-standardised final variant (FIPS 203).
    MLKEM1024,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Kyber768 => write!(f, "Kyber768"),
            KeyType::Kyber1024 => write!(f, "Kyber1024"),
            KeyType::MLKEM1024 => write!(f, "MLKEM1024"),
        }
    }
}

impl KeyType {
    /// Returns the one-byte wire identifier for this key type.
    pub fn value(&self) -> u8 {
        match self {
            KeyType::Kyber768 => 0x07,
            KeyType::Kyber1024 => 0x08,
            KeyType::MLKEM1024 => 0x0A,
        }
    }

    /// Returns the static parameter set for this KEM variant.
    pub const fn parameters(&self) -> &'static dyn DynParameters {
        match self {
            KeyType::Kyber768 => &kyber768::Parameters,
            KeyType::Kyber1024 => &kyber1024::Parameters,
            KeyType::MLKEM1024 => &mlkem1024::Parameters,
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = BadKEMKeyType;

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        match x {
            0x07 => Ok(KeyType::Kyber768),
            0x08 => Ok(KeyType::Kyber1024),
            0x0A => Ok(KeyType::MLKEM1024),
            t => Err(BadKEMKeyType(t)),
        }
    }
}

/// Error returned when a byte value does not correspond to a known [`KeyType`].
#[derive(Debug, Clone)]
pub struct BadKEMKeyType(pub u8);

impl std::fmt::Display for BadKEMKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bad KEM key type {:#x}", self.0)
    }
}

impl std::error::Error for BadKEMKeyType {}

/// Error returned when key material has an unexpected byte length for the chosen KEM variant.
#[derive(Debug, Clone, Copy)]
pub struct BadKEMKeyLength;

impl std::fmt::Display for BadKEMKeyLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bad KEM key length")
    }
}

impl std::error::Error for BadKEMKeyLength {}

/// Errors that can occur during KEM decapsulation.
#[derive(Debug, Clone, Copy)]
pub enum DecapsulateError {
    /// The secret key bytes have an incorrect length for the chosen KEM variant.
    BadKeyLength,
    /// The ciphertext bytes have an incorrect length or are otherwise malformed.
    BadCiphertext,
}

impl std::fmt::Display for DecapsulateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecapsulateError::BadKeyLength => write!(f, "bad key length"),
            DecapsulateError::BadCiphertext => write!(f, "bad ciphertext"),
        }
    }
}

impl std::error::Error for DecapsulateError {}

/// Type-level marker for public key material.
pub struct Public;

/// Type-level marker for secret key material.
pub struct Secret;

/// Trait for types whose byte length is known at compile time.
pub trait ConstantLength {
    /// The fixed byte length of this type.
    const LENGTH: usize;
}

/// Generic byte container for KEM key material, parameterised by a phantom marker type.
///
/// Secret variants are zeroed on drop via [`Zeroize`]. The inner bytes are intentionally
/// opaque — use [`AsRef<[u8]>`] to access them.
#[derive(Clone, Zeroize)]
pub struct KeyMaterial<T> {
    data: Box<[u8]>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> KeyMaterial<T> {
    /// Wraps raw boxed bytes into a [`KeyMaterial`].
    pub fn new(data: Box<[u8]>) -> Self {
        Self {
            data,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T> From<Vec<u8>> for KeyMaterial<T> {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data.into_boxed_slice())
    }
}

impl<T> From<Box<[u8]>> for KeyMaterial<T> {
    fn from(data: Box<[u8]>) -> Self {
        Self::new(data)
    }
}

impl<T, const N: usize> From<[u8; N]> for KeyMaterial<T> {
    fn from(data: [u8; N]) -> Self {
        Self::new(data.to_vec().into_boxed_slice())
    }
}

impl<const SIZE: usize> From<libcrux_ml_kem::MlKemPublicKey<SIZE>> for KeyMaterial<Public> {
    fn from(value: libcrux_ml_kem::MlKemPublicKey<SIZE>) -> Self {
        KeyMaterial::new(value.as_ref().into())
    }
}

impl<const SIZE: usize> From<libcrux_ml_kem::MlKemPrivateKey<SIZE>> for KeyMaterial<Secret> {
    fn from(value: libcrux_ml_kem::MlKemPrivateKey<SIZE>) -> Self {
        KeyMaterial::new(value.as_ref().into())
    }
}

impl<T> AsRef<[u8]> for KeyMaterial<T> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<T> fmt::Debug for KeyMaterial<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("len", &self.data.len())
            .finish()
    }
}

/// Raw shared secret bytes produced by encapsulation or decapsulation.
pub type SharedSecret = Box<[u8]>;

/// Raw ciphertext bytes produced by encapsulation.
pub type RawCiphertext = Box<[u8]>;

/// Static compile-time parameters for a KEM algorithm variant.
pub trait Parameters: Send + Sync {
    /// The [`KeyType`] tag identifying this variant on the wire.
    const KEY_TYPE: KeyType;
    /// Byte length of a serialised public key.
    const PUBLIC_KEY_LENGTH: usize;
    /// Byte length of a serialised secret key.
    const SECRET_KEY_LENGTH: usize;
    /// Byte length of a KEM ciphertext.
    const CIPHERTEXT_LENGTH: usize;
    /// Byte length of the derived shared secret.
    const SHARED_SECRET_LENGTH: usize;

    /// Generates a fresh keypair using `csprng`.
    fn generate<R: CryptoRng + ?Sized>(
        csprng: &mut R,
    ) -> (KeyMaterial<Public>, KeyMaterial<Secret>);

    /// Encapsulates a shared secret under `pub_key`, returning `(shared_secret, ciphertext)`.
    ///
    /// # Errors
    ///
    /// Returns [`BadKEMKeyLength`] if `pub_key` has an unexpected byte length.
    fn encapsulate<R: CryptoRng + ?Sized>(
        pub_key: &KeyMaterial<Public>,
        csprng: &mut R,
    ) -> Result<(SharedSecret, RawCiphertext), BadKEMKeyLength>;

    /// Decapsulates `ciphertext` using `secret_key` and returns the shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`DecapsulateError`] if the key or ciphertext length is invalid.
    fn decapsulate(
        secret_key: &KeyMaterial<Secret>,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, DecapsulateError>;
}

/// Object-safe mirror of [`Parameters`] for dynamic dispatch via [`KeyType::parameters`].
pub trait DynParameters: Send + Sync {
    /// Returns the [`KeyType`] tag for this variant.
    fn key_type(&self) -> KeyType;
    /// Returns the public key byte length.
    fn public_key_length(&self) -> usize;
    /// Returns the secret key byte length.
    fn secret_key_length(&self) -> usize;
    /// Returns the ciphertext byte length.
    fn ciphertext_length(&self) -> usize;
    /// Returns the shared secret byte length.
    fn shared_secret_length(&self) -> usize;
}

impl<P: Parameters> DynParameters for P {
    fn key_type(&self) -> KeyType {
        P::KEY_TYPE
    }
    fn public_key_length(&self) -> usize {
        P::PUBLIC_KEY_LENGTH
    }
    fn secret_key_length(&self) -> usize {
        P::SECRET_KEY_LENGTH
    }
    fn ciphertext_length(&self) -> usize {
        P::CIPHERTEXT_LENGTH
    }
    fn shared_secret_length(&self) -> usize {
        P::SHARED_SECRET_LENGTH
    }
}

/// A matched KEM keypair holding both the public and secret key.
pub struct KeyPair {
    /// The public half; safe to share for encapsulation.
    pub public_key: PublicKey,
    /// The secret half; used for decapsulation. Zeroed on drop.
    pub secret_key: SecretKey,
}

impl KeyPair {
    /// Generates a fresh [`KeyPair`] for `key_type` using `csprng`.
    pub fn generate<R: CryptoRng + ?Sized>(key_type: KeyType, csprng: &mut R) -> Self {
        let (pk_material, sk_material) = match key_type {
            KeyType::Kyber768 => kyber768::Parameters::generate(csprng),
            KeyType::Kyber1024 => kyber1024::Parameters::generate(csprng),
            KeyType::MLKEM1024 => mlkem1024::Parameters::generate(csprng),
        };

        Self {
            public_key: PublicKey {
                key_type,
                key_material: pk_material,
            },
            secret_key: SecretKey {
                key_type,
                key_material: sk_material,
            },
        }
    }

    /// Generates a fresh [`KeyPair`] using the OS RNG.
    ///
    /// Prefer this over [`generate`][Self::generate] when the caller does not already hold
    /// a compatible RNG, to avoid rand version conflicts across crate boundaries.
    pub fn generate_with_os_rng(key_type: KeyType) -> Self {
        Self::generate(key_type, &mut rand::rng())
    }
}

/// A KEM public key used to encapsulate shared secrets.
pub struct PublicKey {
    key_type: KeyType,
    key_material: KeyMaterial<Public>,
}

impl PublicKey {
    /// Encapsulates a fresh shared secret under this public key.
    ///
    /// Returns `(shared_secret, ciphertext)`. Send `ciphertext` to the holder of the
    /// corresponding [`SecretKey`], who calls [`SecretKey::decapsulate`] to recover
    /// the same `shared_secret`.
    ///
    /// # Errors
    ///
    /// Returns [`BadKEMKeyLength`] if the stored key material has an unexpected length.
    pub fn encapsulate<R: CryptoRng + ?Sized>(
        &self,
        csprng: &mut R,
    ) -> Result<(SharedSecret, RawCiphertext), BadKEMKeyLength> {
        match self.key_type {
            KeyType::Kyber768 => kyber768::Parameters::encapsulate(&self.key_material, csprng),
            KeyType::Kyber1024 => kyber1024::Parameters::encapsulate(&self.key_material, csprng),
            KeyType::MLKEM1024 => mlkem1024::Parameters::encapsulate(&self.key_material, csprng),
        }
    }

    /// Encapsulates using the OS RNG.
    ///
    /// Convenience wrapper over [`encapsulate`][Self::encapsulate] that avoids rand
    /// version conflicts across crate boundaries.
    pub fn encapsulate_with_os_rng(
        &self,
    ) -> Result<(SharedSecret, RawCiphertext), BadKEMKeyLength> {
        self.encapsulate(&mut rand::rng())
    }

    /// Serialises the public key to wire format: one type-prefix byte followed by the raw bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.key_material.data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(&self.key_material.data);
        result
    }

    /// Deserialises a public key from its wire-format byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`BadKEMKeyType`] if `data` is empty or the type byte is unrecognised.
    pub fn deserialize(data: &[u8]) -> Result<Self, BadKEMKeyType> {
        if data.is_empty() {
            return Err(BadKEMKeyType(0));
        }
        let key_type = KeyType::try_from(data[0])?;
        let key_material = KeyMaterial::from(data[1..].to_vec());
        Ok(Self {
            key_type,
            key_material,
        })
    }
}

/// A KEM secret key used to decapsulate shared secrets. Zeroed on drop.
pub struct SecretKey {
    key_type: KeyType,
    key_material: KeyMaterial<Secret>,
}

impl SecretKey {
    /// Decapsulates `ciphertext` and returns the shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`DecapsulateError`] if the key or ciphertext length is invalid.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret, DecapsulateError> {
        match self.key_type {
            KeyType::Kyber768 => kyber768::Parameters::decapsulate(&self.key_material, ciphertext),
            KeyType::Kyber1024 => {
                kyber1024::Parameters::decapsulate(&self.key_material, ciphertext)
            }
            KeyType::MLKEM1024 => {
                mlkem1024::Parameters::decapsulate(&self.key_material, ciphertext)
            }
        }
    }

    /// Serialises the secret key to wire format: one type-prefix byte followed by the raw bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.key_material.data.len());
        result.push(self.key_type.value());
        result.extend_from_slice(&self.key_material.data);
        result
    }

    /// Deserialises a secret key from its wire-format byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`BadKEMKeyType`] if `data` is empty or the type byte is unrecognised.
    pub fn deserialize(data: &[u8]) -> Result<Self, BadKEMKeyType> {
        if data.is_empty() {
            return Err(BadKEMKeyType(0));
        }
        let key_type = KeyType::try_from(data[0])?;
        let key_material = KeyMaterial::from(data[1..].to_vec());
        Ok(Self {
            key_type,
            key_material,
        })
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.key_material.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber1024_roundtrip() {
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(KeyType::Kyber1024, &mut rng);

        let (ss_sender, ciphertext) = keypair
            .public_key
            .encapsulate(&mut rng)
            .expect("encapsulation works");
        let ss_recipient = keypair
            .secret_key
            .decapsulate(&ciphertext)
            .expect("decapsulation works");

        assert_eq!(ss_sender, ss_recipient);
    }

    #[test]
    fn test_kyber768_roundtrip() {
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(KeyType::Kyber768, &mut rng);

        let (ss_sender, ciphertext) = keypair
            .public_key
            .encapsulate(&mut rng)
            .expect("encapsulation works");
        let ss_recipient = keypair
            .secret_key
            .decapsulate(&ciphertext)
            .expect("decapsulation works");

        assert_eq!(ss_sender, ss_recipient);
    }

    #[test]
    fn test_serialization() {
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(KeyType::Kyber1024, &mut rng);

        let pk_bytes = keypair.public_key.serialize();
        let pk_restored = PublicKey::deserialize(&pk_bytes).expect("deserialization works");

        assert_eq!(pk_restored.key_type, KeyType::Kyber1024);
    }
}
