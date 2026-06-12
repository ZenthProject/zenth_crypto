//
// Array derivation utilities for cryptographic protocols
//
// These functions help split KDF output into multiple fixed-size arrays,
// which is common in protocols like Double Ratchet.
//

/// Derive multiple fixed-size arrays from a single derivation function.
///
/// This is a helper that allocates a buffer of size N1 + N2 + N3, calls
/// the provided derivation function to fill it, then splits the result
/// into three separate arrays.
///
/// # Type Parameters
/// * `N1` - Size of first output array
/// * `N2` - Size of second output array
/// * `N3` - Size of third output array (can be 0)
///
/// # Arguments
/// * `derive` - A closure that fills the provided byte slice
///
/// # Returns
/// A tuple of three arrays with the derived key material
///
/// # Example
/// ```
/// use kdf::arrays::derive_arrays;
/// use hkdf::Hkdf;
/// use sha2::Sha256;
///
/// // Derive root_key (32 bytes) and chain_key (32 bytes) from HKDF
/// let (root_key, chain_key, []): ([u8; 32], [u8; 32], [u8; 0]) = derive_arrays(|bytes| {
///     Hkdf::<Sha256>::new(Some(b"salt"), b"input")
///         .expand(b"WhisperRatchet", bytes)
///         .expect("valid length");
/// });
/// ```
pub fn derive_arrays<const N1: usize, const N2: usize, const N3: usize>(
    derive: impl FnOnce(&mut [u8]),
) -> ([u8; N1], [u8; N2], [u8; N3]) {
    let Ok(result) = try_derive_arrays::<N1, N2, N3, std::convert::Infallible>(move |buffer| {
        derive(buffer);
        Ok(())
    });
    result
}

/// Fallible version of `derive_arrays`.
///
/// Same as `derive_arrays` but the derivation function can return an error.
///
/// # Type Parameters
/// * `N1` - Size of first output array
/// * `N2` - Size of second output array
/// * `N3` - Size of third output array (can be 0)
/// * `E` - Error type
///
/// # Arguments
/// * `derive` - A closure that fills the provided byte slice, may fail
///
/// # Returns
/// `Ok((array1, array2, array3))` on success, or the derivation error
#[allow(clippy::type_complexity)]
pub fn try_derive_arrays<const N1: usize, const N2: usize, const N3: usize, E>(
    derive: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> Result<([u8; N1], [u8; N2], [u8; N3]), E> {
    let total = N1 + N2 + N3;
    let mut buffer = vec![0u8; total];
    derive(&mut buffer)?;

    let mut arr1 = [0u8; N1];
    let mut arr2 = [0u8; N2];
    let mut arr3 = [0u8; N3];

    arr1.copy_from_slice(&buffer[..N1]);
    arr2.copy_from_slice(&buffer[N1..N1 + N2]);
    arr3.copy_from_slice(&buffer[N1 + N2..]);

    Ok((arr1, arr2, arr3))
}

/// Derive two fixed-size arrays (convenience wrapper).
///
/// # Example
/// ```
/// use kdf::arrays::derive_arrays_2;
///
/// let (key1, key2): ([u8; 32], [u8; 32]) = derive_arrays_2(|bytes| {
///     // Fill with your KDF
///     bytes.fill(0xAB);
/// });
/// ```
pub fn derive_arrays_2<const N1: usize, const N2: usize>(
    derive: impl FnOnce(&mut [u8]),
) -> ([u8; N1], [u8; N2]) {
    let (a, b, []): ([u8; N1], [u8; N2], [u8; 0]) = derive_arrays(derive);
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_arrays_basic() {
        let (a, b, c): ([u8; 4], [u8; 4], [u8; 4]) = derive_arrays(|bytes| {
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = i as u8;
            }
        });

        assert_eq!(a, [0, 1, 2, 3]);
        assert_eq!(b, [4, 5, 6, 7]);
        assert_eq!(c, [8, 9, 10, 11]);
    }

    #[test]
    fn test_derive_arrays_empty_third() {
        let (a, b, []): ([u8; 32], [u8; 32], [u8; 0]) = derive_arrays(|bytes| {
            bytes.fill(0xFF);
        });

        assert_eq!(a, [0xFF; 32]);
        assert_eq!(b, [0xFF; 32]);
    }

    #[test]
    fn test_derive_arrays_with_hkdf() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let root_key = [0x42; 32];
        let shared_secret = [0x13; 32];

        let (new_root, chain_key, []): ([u8; 32], [u8; 32], [u8; 0]) = derive_arrays(|bytes| {
            Hkdf::<Sha256>::new(Some(&root_key), &shared_secret)
                .expand(b"WhisperRatchet", bytes)
                .expect("valid length");
        });

        assert_eq!(new_root.len(), 32);
        assert_eq!(chain_key.len(), 32);
        assert_ne!(new_root, chain_key);
    }

    #[test]
    fn test_derive_arrays_message_keys() {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let chain_key_seed = [0x8a; 32];

        // Derive cipher_key (32), mac_key (32), iv (16) - like Signal
        let (cipher_key, mac_key, iv): ([u8; 32], [u8; 32], [u8; 16]) = derive_arrays(|bytes| {
            Hkdf::<Sha256>::new(None, &chain_key_seed)
                .expand(b"WhisperMessageKeys", bytes)
                .expect("valid length");
        });

        assert_eq!(cipher_key.len(), 32);
        assert_eq!(mac_key.len(), 32);
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn test_try_derive_arrays_success() {
        let result: Result<([u8; 8], [u8; 8], [u8; 0]), &str> = try_derive_arrays(|bytes| {
            bytes.fill(0xAB);
            Ok(())
        });

        assert!(result.is_ok());
        let (a, b, []) = result.unwrap();
        assert_eq!(a, [0xAB; 8]);
        assert_eq!(b, [0xAB; 8]);
    }

    #[test]
    fn test_try_derive_arrays_failure() {
        let result: Result<([u8; 8], [u8; 8], [u8; 0]), &str> =
            try_derive_arrays(|_bytes| Err("derivation failed"));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "derivation failed");
    }

    #[test]
    fn test_derive_arrays_2() {
        let (a, b): ([u8; 16], [u8; 16]) = derive_arrays_2(|bytes| {
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = (i * 2) as u8;
            }
        });

        assert_eq!(a[0], 0);
        assert_eq!(a[15], 30);
        assert_eq!(b[0], 32);
        assert_eq!(b[15], 62);
    }
}
