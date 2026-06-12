//! X3DH pre-key bundle.
//!
//! Contains the public keys that Bob publishes to the server so that Alice
//! can initiate a session without Bob being online.

use super::keys::{IdentityKey, EC_KEY_SIZE, SIGNATURE_SIZE};
use crate::errors::{RatchetError, Result};

/// Pre-key bundle containing all public keys needed to initiate X3DH.
///
/// This is what Bob publishes to the server.
/// Alice fetches this bundle to initiate a session.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Registration ID (device-specific identifier)
    pub registration_id: u32,

    /// Device ID (for multi-device support)
    pub device_id: u32,

    /// Bob's identity key (long-term public key)
    pub identity_key: IdentityKey,

    /// Signed pre-key ID
    pub signed_pre_key_id: u32,

    /// Signed pre-key public key
    pub signed_pre_key: [u8; EC_KEY_SIZE],

    /// Signature of signed pre-key by identity key
    pub signed_pre_key_signature: [u8; SIGNATURE_SIZE],

    /// One-time pre-key ID (optional)
    pub one_time_pre_key_id: Option<u32>,

    /// One-time pre-key public key (optional)
    pub one_time_pre_key: Option<[u8; EC_KEY_SIZE]>,

    /// Kyber pre-key ID (for post-quantum, optional)
    pub kyber_pre_key_id: Option<u32>,

    /// Kyber pre-key public key (optional, for PQXDH)
    pub kyber_pre_key: Option<Vec<u8>>,

    /// Kyber pre-key signature (optional)
    pub kyber_pre_key_signature: Option<[u8; SIGNATURE_SIZE]>,
}

impl PreKeyBundle {
    /// Create a new pre-key bundle (without Kyber).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: u32,
        device_id: u32,
        identity_key: IdentityKey,
        signed_pre_key_id: u32,
        signed_pre_key: [u8; EC_KEY_SIZE],
        signed_pre_key_signature: [u8; SIGNATURE_SIZE],
        one_time_pre_key_id: Option<u32>,
        one_time_pre_key: Option<[u8; EC_KEY_SIZE]>,
    ) -> Self {
        Self {
            registration_id,
            device_id,
            identity_key,
            signed_pre_key_id,
            signed_pre_key,
            signed_pre_key_signature,
            one_time_pre_key_id,
            one_time_pre_key,
            kyber_pre_key_id: None,
            kyber_pre_key: None,
            kyber_pre_key_signature: None,
        }
    }

    /// Create a new pre-key bundle with Kyber (PQXDH).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_kyber(
        registration_id: u32,
        device_id: u32,
        identity_key: IdentityKey,
        signed_pre_key_id: u32,
        signed_pre_key: [u8; EC_KEY_SIZE],
        signed_pre_key_signature: [u8; SIGNATURE_SIZE],
        one_time_pre_key_id: Option<u32>,
        one_time_pre_key: Option<[u8; EC_KEY_SIZE]>,
        kyber_pre_key_id: u32,
        kyber_pre_key: Vec<u8>,
        kyber_pre_key_signature: [u8; SIGNATURE_SIZE],
    ) -> Self {
        Self {
            registration_id,
            device_id,
            identity_key,
            signed_pre_key_id,
            signed_pre_key,
            signed_pre_key_signature,
            one_time_pre_key_id,
            one_time_pre_key,
            kyber_pre_key_id: Some(kyber_pre_key_id),
            kyber_pre_key: Some(kyber_pre_key),
            kyber_pre_key_signature: Some(kyber_pre_key_signature),
        }
    }

    /// Verify all signatures in the bundle.
    ///
    /// Returns Ok(()) if all signatures are valid.
    pub fn verify(&self) -> Result<()> {
        if !self
            .identity_key
            .verify_signature(&self.signed_pre_key, &self.signed_pre_key_signature)
        {
            return Err(RatchetError::InvalidMessage(
                "signed pre-key signature verification failed".to_string(),
            ));
        }

        if let (Some(kyber_pk), Some(kyber_sig)) =
            (&self.kyber_pre_key, &self.kyber_pre_key_signature)
        {
            if !self.identity_key.verify_signature(kyber_pk, kyber_sig) {
                return Err(RatchetError::InvalidMessage(
                    "Kyber pre-key signature verification failed".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Check if this bundle has Kyber (post-quantum) support.
    pub fn has_kyber(&self) -> bool {
        self.kyber_pre_key.is_some()
    }

    /// Check if this bundle has a one-time pre-key.
    pub fn has_one_time_pre_key(&self) -> bool {
        self.one_time_pre_key.is_some()
    }
}

/// Builder for PreKeyBundle.
#[derive(Default)]
pub struct PreKeyBundleBuilder {
    registration_id: Option<u32>,
    device_id: Option<u32>,
    identity_key: Option<IdentityKey>,
    signed_pre_key_id: Option<u32>,
    signed_pre_key: Option<[u8; EC_KEY_SIZE]>,
    signed_pre_key_signature: Option<[u8; SIGNATURE_SIZE]>,
    one_time_pre_key_id: Option<u32>,
    one_time_pre_key: Option<[u8; EC_KEY_SIZE]>,
    kyber_pre_key_id: Option<u32>,
    kyber_pre_key: Option<Vec<u8>>,
    kyber_pre_key_signature: Option<[u8; SIGNATURE_SIZE]>,
}

impl PreKeyBundleBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn registration_id(mut self, id: u32) -> Self {
        self.registration_id = Some(id);
        self
    }

    pub fn device_id(mut self, id: u32) -> Self {
        self.device_id = Some(id);
        self
    }

    pub fn identity_key(mut self, key: IdentityKey) -> Self {
        self.identity_key = Some(key);
        self
    }

    pub fn signed_pre_key(
        mut self,
        id: u32,
        public_key: [u8; EC_KEY_SIZE],
        signature: [u8; SIGNATURE_SIZE],
    ) -> Self {
        self.signed_pre_key_id = Some(id);
        self.signed_pre_key = Some(public_key);
        self.signed_pre_key_signature = Some(signature);
        self
    }

    pub fn one_time_pre_key(mut self, id: u32, public_key: [u8; EC_KEY_SIZE]) -> Self {
        self.one_time_pre_key_id = Some(id);
        self.one_time_pre_key = Some(public_key);
        self
    }

    pub fn kyber_pre_key(
        mut self,
        id: u32,
        public_key: Vec<u8>,
        signature: [u8; SIGNATURE_SIZE],
    ) -> Self {
        self.kyber_pre_key_id = Some(id);
        self.kyber_pre_key = Some(public_key);
        self.kyber_pre_key_signature = Some(signature);
        self
    }

    pub fn build(self) -> Result<PreKeyBundle> {
        Ok(PreKeyBundle {
            registration_id: self
                .registration_id
                .ok_or_else(|| RatchetError::InvalidMessage("missing registration_id".into()))?,
            device_id: self
                .device_id
                .ok_or_else(|| RatchetError::InvalidMessage("missing device_id".into()))?,
            identity_key: self
                .identity_key
                .ok_or_else(|| RatchetError::InvalidMessage("missing identity_key".into()))?,
            signed_pre_key_id: self
                .signed_pre_key_id
                .ok_or_else(|| RatchetError::InvalidMessage("missing signed_pre_key_id".into()))?,
            signed_pre_key: self
                .signed_pre_key
                .ok_or_else(|| RatchetError::InvalidMessage("missing signed_pre_key".into()))?,
            signed_pre_key_signature: self.signed_pre_key_signature.ok_or_else(|| {
                RatchetError::InvalidMessage("missing signed_pre_key_signature".into())
            })?,
            one_time_pre_key_id: self.one_time_pre_key_id,
            one_time_pre_key: self.one_time_pre_key,
            kyber_pre_key_id: self.kyber_pre_key_id,
            kyber_pre_key: self.kyber_pre_key,
            kyber_pre_key_signature: self.kyber_pre_key_signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::keys::{IdentityKeyPair, SignedPreKey};
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_bundle_creation() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);
        let signed_prekey = SignedPreKey::generate(1, &identity, &mut rng);

        let bundle = PreKeyBundle::new(
            12345,
            1,
            identity.public_key(),
            signed_prekey.id,
            *signed_prekey.public_key(),
            signed_prekey.signature,
            None,
            None,
        );

        assert_eq!(bundle.registration_id, 12345);
        assert!(!bundle.has_one_time_pre_key());
        assert!(!bundle.has_kyber());
    }

    #[test]
    fn test_bundle_verification() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);
        let signed_prekey = SignedPreKey::generate(1, &identity, &mut rng);

        let bundle = PreKeyBundle::new(
            12345,
            1,
            identity.public_key(),
            signed_prekey.id,
            *signed_prekey.public_key(),
            signed_prekey.signature,
            None,
            None,
        );

        assert!(bundle.verify().is_ok());
    }

    #[test]
    fn test_bundle_verification_fails_with_wrong_signature() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);
        let signed_prekey = SignedPreKey::generate(1, &identity, &mut rng);

        // Use a different identity key for verification
        let other_identity = IdentityKeyPair::generate(&mut rng);

        let bundle = PreKeyBundle::new(
            12345,
            1,
            other_identity.public_key(), // Wrong identity key
            signed_prekey.id,
            *signed_prekey.public_key(),
            signed_prekey.signature,
            None,
            None,
        );

        assert!(bundle.verify().is_err());
    }

    #[test]
    fn test_bundle_builder() {
        let mut rng = OsRng;
        let identity = IdentityKeyPair::generate(&mut rng);
        let signed_prekey = SignedPreKey::generate(1, &identity, &mut rng);

        let bundle = PreKeyBundleBuilder::new()
            .registration_id(12345)
            .device_id(1)
            .identity_key(identity.public_key())
            .signed_pre_key(
                signed_prekey.id,
                *signed_prekey.public_key(),
                signed_prekey.signature,
            )
            .build()
            .unwrap();

        assert!(bundle.verify().is_ok());
    }
}
