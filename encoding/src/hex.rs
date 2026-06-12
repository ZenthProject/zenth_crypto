use hex;

/// Hexadecimal encoding and decoding operations (lowercase, no prefix).
pub trait HexEncodeSecure {
    /// Encodes `data` as a lowercase hexadecimal string (e.g. `"deadbeef"`).
    fn hexencode(data: &[u8]) -> String;

    /// Decodes a hexadecimal string and returns the raw byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error string if `encoded_message` contains non-hex characters
    /// or has an odd number of characters.
    fn hexdecode(encoded_message: &str) -> Result<Vec<u8>, String>;

    /// Decodes a hexadecimal string and interprets the result as UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns an error string if `encoded_message` is not valid hex
    /// or if the decoded bytes are not valid UTF-8.
    fn hexdecode_to_string(encoded_message: &str) -> Result<String, String>;
}

/// Concrete implementation of [`HexEncodeSecure`] using lowercase hex encoding.
pub struct HexEncodeImpl;

impl HexEncodeSecure for HexEncodeImpl {
    fn hexencode(data: &[u8]) -> String {
        hex::encode(data)
    }

    fn hexdecode(encoded_message: &str) -> Result<Vec<u8>, String> {
        hex::decode(encoded_message).map_err(|e| format!("Hex decode error: {}", e))
    }

    fn hexdecode_to_string(encoded_message: &str) -> Result<String, String> {
        let bytes = hex::decode(encoded_message).map_err(|e| format!("Hex decode error: {}", e))?;
        String::from_utf8(bytes).map_err(|e| format!("UTF-8 decode error: {}", e))
    }
}
