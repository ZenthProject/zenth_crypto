use hbs_lms::signature::{Signature as SignatureTrait, SignerMut, Verifier};
use hbs_lms::{
    HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_256, SigningKey, VerifyingKey,
};
use std::fmt;
use std::sync::{Arc, Mutex};

/// Errors that can occur during LMS key generation, signing, or verification.
#[derive(Debug, Clone)]
pub enum LmsError {
    /// The supplied private key bytes do not represent a valid LMS signing key.
    InvalidPrivateKey,
    /// The supplied public key bytes do not represent a valid LMS verifying key.
    InvalidPublicKey,
    /// The supplied signature bytes cannot be deserialised as a valid LMS signature.
    InvalidSignature,
    /// The signature is well-formed but does not verify against the provided message and key.
    VerificationFailed,
    /// The signing key has reached its maximum signature count and must be replaced.
    KeyExhausted,
    /// Key generation failed, typically due to an unsupported tree height parameter.
    KeyGenerationFailed,
}

impl fmt::Display for LmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LmsError::InvalidPrivateKey => write!(f, "Invalid private key format"),
            LmsError::InvalidPublicKey => write!(f, "Invalid public key format"),
            LmsError::InvalidSignature => write!(f, "Invalid signature format"),
            LmsError::VerificationFailed => write!(f, "Signature verification failed"),
            LmsError::KeyExhausted => {
                write!(f, "Key has been exhausted - maximum signatures reached")
            }
            LmsError::KeyGenerationFailed => write!(f, "Key generation failed"),
        }
    }
}

impl std::error::Error for LmsError {}

/// A Leighton-Micali keypair with built-in stateful signature tracking.
///
/// LMS private keys are finite: a tree of height `h` allows exactly `2^h` signatures.
/// This struct wraps both the raw key material and an atomic counter so that
/// exhaustion is detected before attempting an invalid signing operation.
///
/// Cloning this struct shares the same counter via [`Arc`], which is intentional —
/// all copies of a keypair see the same usage state.
pub struct LmsKeyPair {
    private_key: Vec<u8>,
    /// The raw public key bytes. May be shared freely for signature verification.
    pub public_key: Vec<u8>,
    signature_counter: Arc<Mutex<u32>>,
    max_signatures: u32,
}

impl LmsKeyPair {
    /// Constructs an [`LmsKeyPair`] from raw key bytes and a signature budget.
    fn new(private_key: Vec<u8>, public_key: Vec<u8>, max_signatures: u32) -> Self {
        Self {
            private_key,
            public_key,
            signature_counter: Arc::new(Mutex::new(0)),
            max_signatures,
        }
    }

    /// Returns the number of signatures produced so far with this keypair.
    pub fn signature_count(&self) -> u32 {
        *self.signature_counter.lock().unwrap()
    }

    /// Returns the maximum number of signatures this keypair may produce (`2^height`).
    pub fn max_signatures(&self) -> u32 {
        self.max_signatures
    }

    /// Returns `true` if the keypair has not yet reached its signature limit.
    pub fn can_sign(&self) -> bool {
        self.signature_count() < self.max_signatures
    }

    /// Returns the number of signatures remaining before the keypair is exhausted.
    pub fn remaining_signatures(&self) -> u32 {
        self.max_signatures.saturating_sub(self.signature_count())
    }

    /// Signs `message` and increments the internal signature counter.
    ///
    /// # Errors
    ///
    /// Returns [`LmsError::KeyExhausted`] if the keypair has reached its signature limit,
    /// or [`LmsError::InvalidPrivateKey`] if the stored key bytes are malformed.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, LmsError> {
        let mut counter = self.signature_counter.lock().unwrap();
        if *counter >= self.max_signatures {
            return Err(LmsError::KeyExhausted);
        }

        let mut signing_key = SigningKey::<Sha256_256>::from_bytes(&self.private_key)
            .map_err(|_| LmsError::InvalidPrivateKey)?;

        let signature = signing_key.sign(message);
        *counter += 1;

        Ok(signature.as_bytes().to_vec())
    }

    /// Verifies `signature` over `message` using this keypair's public key.
    ///
    /// # Errors
    ///
    /// Returns [`LmsError::InvalidPublicKey`] if the stored public key is malformed,
    /// [`LmsError::InvalidSignature`] if `signature` cannot be deserialised, or
    /// [`LmsError::VerificationFailed`] if the signature does not match.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), LmsError> {
        let verifying_key = VerifyingKey::<Sha256_256>::from_bytes(&self.public_key)
            .map_err(|_| LmsError::InvalidPublicKey)?;

        let signature_obj =
            hbs_lms::Signature::from_bytes(signature).map_err(|_| LmsError::InvalidSignature)?;

        verifying_key
            .verify(message, &signature_obj)
            .map_err(|_| LmsError::VerificationFailed)
    }
}

/// Generates a new LMS keypair with the default tree height of 10 (`2^10 = 1 024` signatures).
///
/// This is the recommended entry point for most use cases. For fine-grained control
/// over the signature budget, use [`generate_keypair_with_height`] instead.
///
/// # Errors
///
/// Propagates any error from [`generate_keypair_with_height`].
pub fn generate_keypair() -> Result<LmsKeyPair, LmsError> {
    generate_keypair_with_height(10)
}

/// Generates a new LMS keypair with a custom Merkle tree height.
///
/// The tree height determines the maximum number of signatures the keypair can produce:
///
/// # Arguments
///
/// * `tree_height` — Merkle tree height. Must be in the range `5..=20`.
///
/// # Errors
///
/// Returns [`LmsError::KeyGenerationFailed`] if `tree_height` is outside `5..=20`
/// or if the underlying key generation fails.
pub fn generate_keypair_with_height(tree_height: u8) -> Result<LmsKeyPair, LmsError> {
    if !(5..=20).contains(&tree_height) {
        return Err(LmsError::KeyGenerationFailed);
    }

    let lms_algorithm = match tree_height {
        5 => LmsAlgorithm::LmsH5,
        10 => LmsAlgorithm::LmsH10,
        15 => LmsAlgorithm::LmsH15,
        20 => LmsAlgorithm::LmsH20,
        _ => LmsAlgorithm::LmsH10,
    };

    let params = [HssParameter::new(LmotsAlgorithm::LmotsW8, lms_algorithm)];
    let mut rng = rand::thread_rng();
    let mut seed = Seed::<Sha256_256>::default();

    use rand::RngCore;
    rng.fill_bytes(seed.as_mut_slice());

    let (signing_key, verifying_key) =
        hbs_lms::keygen(&params, &seed, None).map_err(|_| LmsError::KeyGenerationFailed)?;

    let max_signatures = 2u32.pow(tree_height as u32);

    Ok(LmsKeyPair::new(
        signing_key.as_slice().to_vec(),
        verifying_key.as_slice().to_vec(),
        max_signatures,
    ))
}

/// Signs `message` with a raw private key byte slice, with no usage tracking.
///
/// # Deprecation
///
/// This function does not enforce the one-time-use constraint of LMS keys.
/// Reusing the same key offset for multiple messages breaks the security proof.
/// Prefer [`LmsKeyPair::sign`], which tracks and enforces the signature budget.
///
/// # Errors
///
/// Returns [`LmsError::InvalidPrivateKey`] if the supplied bytes are malformed.
#[deprecated(since = "0.1.0", note = "Use LmsKeyPair::sign() for stateful signing")]
pub fn sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, LmsError> {
    let mut signing_key = SigningKey::<Sha256_256>::from_bytes(private_key)
        .map_err(|_| LmsError::InvalidPrivateKey)?;

    let signature = signing_key.sign(message);
    Ok(signature.as_bytes().to_vec())
}

/// Verifies an LMS `signature` over `message` using a raw public key byte slice.
///
/// This function is stateless and does not require an [`LmsKeyPair`], making it
/// suitable for verifier-only contexts where only the public key is available.
///
/// # Errors
///
/// Returns [`LmsError::InvalidPublicKey`] if the key bytes are malformed,
/// [`LmsError::InvalidSignature`] if the signature cannot be deserialised, or
/// [`LmsError::VerificationFailed`] if the signature is invalid for the given message.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), LmsError> {
    let verifying_key = VerifyingKey::<Sha256_256>::from_bytes(public_key)
        .map_err(|_| LmsError::InvalidPublicKey)?;

    let signature_obj =
        hbs_lms::Signature::from_bytes(signature).map_err(|_| LmsError::InvalidSignature)?;

    verifying_key
        .verify(message, &signature_obj)
        .map_err(|_| LmsError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair().expect("Key generation failed");
        assert!(!keypair.public_key.is_empty());
        assert_eq!(keypair.signature_count(), 0);
        assert_eq!(keypair.max_signatures(), 1024);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = generate_keypair().expect("Key generation failed");
        let message = b"Hello, post-quantum world!";
        let signature = keypair.sign(message).expect("Signing failed");
        assert!(!signature.is_empty());
        assert_eq!(keypair.signature_count(), 1);
        keypair
            .verify(message, &signature)
            .expect("Verification failed");
    }

    #[test]
    fn test_key_exhaustion() {
        let keypair = generate_keypair_with_height(5).expect("Key generation failed");
        assert_eq!(keypair.max_signatures(), 32);
        for i in 0..32 {
            let msg = format!("Message {}", i);
            keypair.sign(msg.as_bytes()).expect("Signing failed");
        }
        assert_eq!(keypair.signature_count(), 32);
        assert!(!keypair.can_sign());
        let result = keypair.sign(b"One too many");
        assert!(matches!(result, Err(LmsError::KeyExhausted)));
    }

    #[test]
    fn test_wrong_message_verification() {
        let keypair = generate_keypair().expect("Key generation failed");
        let message = b"Original message";
        let wrong_message = b"Different message";
        let signature = keypair.sign(message).expect("Signing failed");
        let result = keypair.verify(wrong_message, &signature);
        assert!(result.is_err());
    }
}
