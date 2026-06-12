use pem::{Pem, encode, parse};

/// PEM encoding and decoding operations (RFC 7468 text format).
///
/// PEM wraps binary DER data in a Base64 block with `-----BEGIN <LABEL>-----`
/// and `-----END <LABEL>-----` headers, making it suitable for text-based
/// key and certificate interchange.
pub trait PemEncodeSecure {
    /// Encodes `data` as a PEM block with the given `label`.
    ///
    /// The label appears in the header and footer lines, e.g. `"PUBLIC KEY"` produces
    /// `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----`.
    fn pemencode(label: &str, data: &[u8]) -> String;

    /// Decodes a PEM block and returns the raw DER byte contents.
    ///
    /// The label is not validated; only the first PEM block in `pem_str` is parsed.
    ///
    /// # Errors
    ///
    /// Returns an error string if `pem_str` does not contain a valid PEM block.
    fn pemdecode(pem_str: &str) -> Result<Vec<u8>, String>;
}

/// Concrete implementation of [`PemEncodeSecure`].
pub struct PemEncodeImpl;

impl PemEncodeSecure for PemEncodeImpl {
    fn pemencode(label: &str, data: &[u8]) -> String {
        let pem_struct = Pem::new(label.to_string(), data.to_vec());
        encode(&pem_struct)
    }

    fn pemdecode(pem_str: &str) -> Result<Vec<u8>, String> {
        let pem = parse(pem_str).map_err(|e| format!("PEM decode error: {}", e))?;
        Ok(pem.contents().to_vec())
    }
}
