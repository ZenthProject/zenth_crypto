use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::fmt;

/// Errors that can occur during a SPAKE2 key exchange.
#[derive(Debug, Clone)]
pub enum Spake2Error {
    /// The key exchange could not be completed; the inner string describes the cause.
    KeyExchangeFailed(String),
    /// The message received from the peer could not be parsed or authenticated.
    InvalidMessage,
    /// The protocol was used in an unexpected state; the inner string describes the cause.
    ProtocolStateError(String),
}

impl fmt::Display for Spake2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Spake2Error::KeyExchangeFailed(msg) => write!(f, "Key exchange failed: {}", msg),
            Spake2Error::InvalidMessage => write!(f, "Invalid message from peer"),
            Spake2Error::ProtocolStateError(msg) => write!(f, "Protocol state error: {}", msg),
        }
    }
}

impl std::error::Error for Spake2Error {}

/// High-level wrapper around the SPAKE2 password-authenticated key exchange protocol.
///
/// SPAKE2 (IETF draft) allows two parties that share a password to establish a strong
/// session key without transmitting the password or exposing it to offline dictionary attacks.
///
/// # Security properties
///
/// - Prevents offline dictionary attacks on the shared password.
/// - Provides implicit key confirmation (mismatched passwords yield different session keys).
/// - Resistant to man-in-the-middle attacks when identities are bound to the exchange.
/// - No trusted setup required.
///
/// # Usage pattern
///
/// In a real deployment, client and server run on separate machines:
///
/// 1. Client calls [`Spake2Wrapper::client_exchange`] → sends the outbound message to the server.
/// 2. Server calls [`Spake2Wrapper::server_exchange`] with the client message → sends its message back.
/// 3. Client calls [`Spake2Wrapper::client_complete_exchange`] with the server message → derives the session key.
pub struct Spake2Wrapper;

impl Spake2Wrapper {
    /// Starts the client side of a SPAKE2 handshake and returns the first outbound message.
    ///
    /// The returned `session_key` is empty at this stage; the actual key is derived once the
    /// server response is processed via [`Spake2Wrapper::client_complete_exchange`].
    ///
    /// # Arguments
    ///
    /// * `password`  — shared password bytes.
    /// * `client_id` — client identity bound into the exchange.
    /// * `server_id` — server identity bound into the exchange.
    ///
    /// # Returns
    ///
    /// `(outbound_message, [])` — the message to send to the server; the key slot is empty
    /// until [`client_complete_exchange`][Spake2Wrapper::client_complete_exchange] is called.
    pub fn client_exchange(
        password: &[u8],
        client_id: &[u8],
        server_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Spake2Error> {
        let (_client_state, client_msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password),
            &Identity::new(client_id),
            &Identity::new(server_id),
        );
        Ok((client_msg, vec![]))
    }

    /// Completes the client side of a SPAKE2 handshake and derives the session key.
    ///
    /// # Arguments
    ///
    /// * `password`   — shared password bytes.
    /// * `client_id`  — client identity bound into the exchange.
    /// * `server_id`  — server identity bound into the exchange.
    /// * `server_msg` — the message received from the server.
    ///
    /// # Returns
    ///
    /// `(client_msg, session_key)` — the client's first message and the derived session key.
    ///
    /// # Errors
    ///
    /// Returns [`Spake2Error::InvalidMessage`] if `server_msg` cannot be authenticated.
    pub fn client_complete_exchange(
        password: &[u8],
        client_id: &[u8],
        server_id: &[u8],
        server_msg: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Spake2Error> {
        let (client_state, client_msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password),
            &Identity::new(client_id),
            &Identity::new(server_id),
        );

        let session_key = client_state
            .finish(server_msg)
            .map_err(|_| Spake2Error::InvalidMessage)?;

        Ok((client_msg, session_key.to_vec()))
    }

    /// Performs the server side of a SPAKE2 handshake in a single step.
    ///
    /// Processes the client's message, derives the session key, and returns the server's
    /// outbound message so the client can complete the exchange.
    ///
    /// # Arguments
    ///
    /// * `password`   — shared password bytes.
    /// * `client_id`  — client identity bound into the exchange.
    /// * `server_id`  — server identity bound into the exchange.
    /// * `client_msg` — the message received from the client.
    ///
    /// # Returns
    ///
    /// `(server_msg, session_key)` — the message to send back to the client and the derived key.
    ///
    /// # Errors
    ///
    /// Returns [`Spake2Error::InvalidMessage`] if `client_msg` cannot be authenticated.
    pub fn server_exchange(
        password: &[u8],
        client_id: &[u8],
        server_id: &[u8],
        client_msg: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Spake2Error> {
        let (server_state, server_msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(password),
            &Identity::new(client_id),
            &Identity::new(server_id),
        );

        let session_key = server_state
            .finish(client_msg)
            .map_err(|_| Spake2Error::InvalidMessage)?;

        Ok((server_msg, session_key.to_vec()))
    }

    /// Simulates a complete client-server SPAKE2 handshake in a single call, for testing.
    ///
    /// Both sides are run in the same process. In production, client and server execute
    /// on separate machines with the messages transported over the network.
    ///
    /// # Returns
    ///
    /// `(client_key, server_key)` — both should be identical if the password matched.
    ///
    /// # Errors
    ///
    /// Returns [`Spake2Error::KeyExchangeFailed`] if either finish step fails or if
    /// the two derived keys do not match (indicating a password mismatch or protocol error).
    pub fn perform_handshake(password: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Spake2Error> {
        let client_id = b"client@example.com";
        let server_id = b"server@example.com";

        let (client_state, client_msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password),
            &Identity::new(client_id),
            &Identity::new(server_id),
        );

        let (server_state, server_msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(password),
            &Identity::new(client_id),
            &Identity::new(server_id),
        );

        let client_key = client_state
            .finish(&server_msg)
            .map_err(|_| Spake2Error::KeyExchangeFailed("Client finish failed".to_string()))?;

        let server_key = server_state
            .finish(&client_msg)
            .map_err(|_| Spake2Error::KeyExchangeFailed("Server finish failed".to_string()))?;

        if client_key != server_key {
            return Err(Spake2Error::KeyExchangeFailed(
                "Keys don't match".to_string(),
            ));
        }

        Ok((client_key.to_vec(), server_key.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_handshake() {
        let password = b"shared_secret_password";
        let (client_key, server_key) =
            Spake2Wrapper::perform_handshake(password).expect("Handshake failed");

        assert_eq!(client_key, server_key);
        assert!(!client_key.is_empty());
    }

    #[test]
    fn test_wrong_password() {
        let client_password = b"password1";
        let server_password = b"password2";

        let client_id = b"alice";
        let server_id = b"bob";

        // Client with password1
        let (client_state, client_msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(client_password),
            &Identity::new(client_id),
            &Identity::new(server_id),
        );

        // Server with password2
        let (server_state, server_msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(server_password),
            &Identity::new(client_id),
            &Identity::new(server_id),
        );

        // Keys should be different
        let client_key = client_state.finish(&server_msg);
        let server_key = server_state.finish(&client_msg);

        // Both should succeed but derive different keys
        assert!(client_key.is_ok());
        assert!(server_key.is_ok());
        assert_ne!(client_key.unwrap(), server_key.unwrap());
    }

    #[test]
    fn test_server_exchange() {
        let password = b"test_password";
        let client_id = b"client";
        let server_id = b"server";

        // Client creates message
        let (_client_state, client_msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password),
            &Identity::new(client_id),
            &Identity::new(server_id),
        );

        // Server processes it
        let result = Spake2Wrapper::server_exchange(password, client_id, server_id, &client_msg);

        assert!(result.is_ok());
        let (_server_msg, session_key) = result.unwrap();
        assert!(!session_key.is_empty());
    }
}
