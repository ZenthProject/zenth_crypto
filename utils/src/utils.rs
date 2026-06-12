// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only

//! Constant-time byte ordering.

use std::cmp::Ordering;

/// Returns `0xFF` if the top bit of `a` is set, `0x00` otherwise.
fn expand_top_bit(a: u8) -> u8 {
    0u8.wrapping_sub(a >> 7)
}

/// Returns `0xFF` if `a == 0`, `0x00` otherwise.
fn ct_is_zero(a: u8) -> u8 {
    expand_top_bit(!a & a.wrapping_sub(1))
}

/// Returns `0xFF` if `a == b`, `0x00` otherwise.
fn ct_is_eq(a: u8, b: u8) -> u8 {
    ct_is_zero(a ^ b)
}

/// Returns `0xFF` if `a < b`, `0x00` otherwise.
fn ct_is_lt(a: u8, b: u8) -> u8 {
    expand_top_bit(a ^ ((a ^ b) | ((a.wrapping_sub(b)) ^ a)))
}

/// Selects `a` if `mask == 0xFF`, `b` if `mask == 0x00`.
fn ct_select(mask: u8, a: u8, b: u8) -> u8 {
    debug_assert!(mask == 0 || mask == 0xFF);
    b ^ (mask & (a ^ b))
}

/// Compare two byte slices in constant time and return their ordering.
///
/// Leaks the relative lengths of `x` and `y` (irrelevant when both have the
/// same size, which is the typical use case for comparing public keys). The
/// final `Ordering` value is also leaked, but this is unavoidable.
///
/// The primary goal is to avoid leaking any additional information about the
/// *content* of the two slices via early loop exit.
pub fn constant_time_cmp(x: &[u8], y: &[u8]) -> Ordering {
    if x.len() < y.len() {
        return Ordering::Less;
    }
    if x.len() > y.len() {
        return Ordering::Greater;
    }

    let mut result: u8 = 0;

    for i in 0..x.len() {
        let a = x[x.len() - 1 - i];
        let b = y[x.len() - 1 - i];

        let is_eq = ct_is_eq(a, b);
        let is_lt = ct_is_lt(a, b);

        result = ct_select(is_eq, result, ct_select(is_lt, 1, 255));
    }

    debug_assert!(result == 0 || result == 1 || result == 255);

    if result == 0 {
        Ordering::Equal
    } else if result == 1 {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

#[cfg(test)]
mod tests {
    use rand::CryptoRng as _;

    use super::*;

    #[test]
    fn test_constant_time_cmp() {
        use rand::random;
        assert_eq!(constant_time_cmp(&[1], &[1]), Ordering::Equal);
        assert_eq!(constant_time_cmp(&[0, 1], &[1]), Ordering::Greater);
        assert_eq!(constant_time_cmp(&[1], &[0, 1]), Ordering::Less);
        assert_eq!(constant_time_cmp(&[2], &[1, 0, 1]), Ordering::Less);

        for len in 1..320 {
            let x: Vec<u8> = (0..len).map(|_| random()).collect();
            let y: Vec<u8> = (0..len).map(|_| random()).collect();
            let expected = x.cmp(&y);
            let result = constant_time_cmp(&x, &y);
            assert_eq!(result, expected);

            let expected = y.cmp(&x);
            let result = constant_time_cmp(&y, &x);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_ct_is_zero() {
        assert_eq!(ct_is_zero(0), 0xFF);

        for i in 1..255 {
            assert_eq!(ct_is_zero(i), 0x00);
        }
    }

    #[test]
    fn test_ct_is_lt() {
        for x in 0..255 {
            for y in 0..255 {
                let expected = if x < y { 0xFF } else { 0 };
                let result = ct_is_lt(x, y);
                assert_eq!(result, expected);
            }
        }
    }

    #[test]
    fn test_ct_is_eq() {
        for x in 0..255 {
            for y in 0..255 {
                let expected = if x == y { 0xFF } else { 0 };
                let result = ct_is_eq(x, y);
                assert_eq!(result, expected);
            }
        }
    }
}
