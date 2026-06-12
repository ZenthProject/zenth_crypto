/// Compare two byte slices for equality in constant time.
///
/// Returns `false` immediately if the lengths differ (which leaks relative sizes,
/// but not content). For equal-length slices the comparison touches every byte
/// regardless of their values, preventing timing side-channels.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}
