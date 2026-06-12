use base64::{Engine, engine::general_purpose};

/// Base64 encoding and decoding operations (standard alphabet, with padding).
pub trait EncodeSecure {
    /// Encodes `data` as a standard Base64 string (RFC 4648, with `=` padding).
    fn base64encode(data: &[u8]) -> String;

    /// Decodes a Base64 string and interprets the result as UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns an error string if `encoded_message` is not valid Base64
    /// or if the decoded bytes are not valid UTF-8.
    fn base64decode(encoded_message: &str) -> Result<String, String>;

    /// Decodes a Base64 string and returns the raw byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error string if `encoded_message` is not valid Base64.
    fn base64_vecdecode(encoded_message: &str) -> Result<Vec<u8>, String>;
}

/// Concrete implementation of [`EncodeSecure`] using the standard Base64 alphabet.
pub struct EncodeImpl;

impl EncodeSecure for EncodeImpl {
    fn base64_vecdecode(encoded_message: &str) -> Result<Vec<u8>, String> {
        general_purpose::STANDARD
            .decode(encoded_message)
            .map_err(|e| format!("Base64 decode error: {}", e))
    }

    fn base64decode(encoded_message: &str) -> Result<String, String> {
        let decoded_bytes = general_purpose::STANDARD
            .decode(encoded_message)
            .map_err(|e| format!("Base64 decode error: {}", e))?;
        String::from_utf8(decoded_bytes).map_err(|e| format!("UTF-8 decode error: {}", e))
    }

    fn base64encode(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }
}
