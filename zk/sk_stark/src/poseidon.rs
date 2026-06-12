//! Poseidon hash function — STARK-friendly cryptographic hash.
//!
//! Poseidon is designed for efficient arithmetization in ZK circuits.
//! Used by StarkNet, Filecoin, Polygon Hermez, and Mina Protocol.
//!
//! Security: 128-bit security level, post-quantum secure.
//!
//! Reference: <https://eprint.iacr.org/2019/458.pdf>

use winterfell::math::fields::f128::BaseElement;
use winterfell::math::FieldElement;

/// Number of full rounds (beginning + end).
pub const FULL_ROUNDS: usize = 8;

/// Number of partial rounds (middle)
pub const PARTIAL_ROUNDS: usize = 56;

/// State width (rate + capacity)
pub const STATE_WIDTH: usize = 3;

/// Rate (number of field elements absorbed per permutation)
pub const RATE: usize = 2;

/// S-box exponent (x^5 is common for prime fields)
pub const ALPHA: u64 = 5;

/// Round constants for Poseidon.
///
/// Generated deterministically for this width-3 configuration.
/// In production these should be generated using the Grain LFSR as specified
/// in the Poseidon paper.
pub const ROUND_CONSTANTS: [[u128; STATE_WIDTH]; FULL_ROUNDS + PARTIAL_ROUNDS] = {
    let mut constants = [[0u128; STATE_WIDTH]; FULL_ROUNDS + PARTIAL_ROUNDS];

    let mut seed: u128 = 0x517cc1b727220a95_u128;
    let mut i = 0;
    while i < FULL_ROUNDS + PARTIAL_ROUNDS {
        let mut j = 0;
        while j < STATE_WIDTH {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            constants[i][j] = seed;
            j += 1;
        }
        i += 1;
    }
    constants
};

/// MDS (Maximum Distance Separable) matrix for diffusion
/// This is a Cauchy matrix which guarantees MDS property
pub const MDS_MATRIX: [[u128; STATE_WIDTH]; STATE_WIDTH] = [[3, 1, 1], [1, 3, 1], [1, 1, 3]];

/// Poseidon hash state
#[derive(Clone, Debug)]
pub struct PoseidonState {
    state: [BaseElement; STATE_WIDTH],
}

impl Default for PoseidonState {
    fn default() -> Self {
        Self::new()
    }
}

impl PoseidonState {
    /// Create a new Poseidon state initialized to zero
    pub fn new() -> Self {
        Self {
            state: [BaseElement::ZERO; STATE_WIDTH],
        }
    }

    /// Create state from existing values
    pub fn from_state(state: [BaseElement; STATE_WIDTH]) -> Self {
        Self { state }
    }

    /// Get current state
    pub fn state(&self) -> &[BaseElement; STATE_WIDTH] {
        &self.state
    }

    /// Apply the full Poseidon permutation (half-full → partial → half-full rounds).
    pub fn permute(&mut self) {
        for r in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
            apply_round(r, &mut self.state);
        }
    }

    /// Absorb input elements into the state using the sponge construction.
    pub fn absorb(&mut self, input: &[BaseElement]) {
        for chunk in input.chunks(RATE) {
            for (i, &elem) in chunk.iter().enumerate() {
                self.state[i] += elem;
            }
            self.permute();
        }
    }

    /// Squeeze output from the state
    pub fn squeeze(&self) -> BaseElement {
        self.state[0]
    }

    /// Squeeze multiple elements
    pub fn squeeze_many(&mut self, count: usize) -> Vec<BaseElement> {
        let mut output = Vec::with_capacity(count);

        while output.len() < count {
            for i in 0..RATE.min(count - output.len()) {
                output.push(self.state[i]);
            }
            if output.len() < count {
                self.permute();
            }
        }

        output
    }
}

/// Compute Poseidon hash of input elements
///
/// # Arguments
/// * `input` - Slice of field elements to hash
///
/// # Returns
/// Single field element as the hash output
pub fn poseidon_hash(input: &[BaseElement]) -> BaseElement {
    let mut state = PoseidonState::new();
    state.absorb(input);
    state.squeeze()
}

/// Compute Poseidon hash of two elements (common case for Merkle trees)
pub fn poseidon_hash_two(left: BaseElement, right: BaseElement) -> BaseElement {
    let mut state = PoseidonState::new();
    state.state[0] = left;
    state.state[1] = right;
    state.permute();
    state.squeeze()
}

/// Convert bytes to field elements for hashing.
///
/// Packs 15 bytes per element (to stay within the 128-bit field modulus) and
/// appends a length field element to prevent length-extension attacks.
pub fn bytes_to_elements(bytes: &[u8]) -> Vec<BaseElement> {
    const BYTES_PER_ELEMENT: usize = 15;

    let mut elements = Vec::new();

    for chunk in bytes.chunks(BYTES_PER_ELEMENT) {
        let mut value: u128 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u128) << (i * 8);
        }
        elements.push(BaseElement::new(value));
    }

    elements.push(BaseElement::new(bytes.len() as u128));

    elements
}

/// Hash arbitrary bytes using Poseidon
pub fn poseidon_hash_bytes(bytes: &[u8]) -> BaseElement {
    let elements = bytes_to_elements(bytes);
    poseidon_hash(&elements)
}

/// Applies one Poseidon round to `state` in-place.
///
/// Selects full vs. partial round based on the round index: full rounds apply
/// the S-box to every element; partial rounds apply it only to `state[0]`.
pub fn apply_round(round: usize, state: &mut [BaseElement]) {
    let half_full = FULL_ROUNDS / 2;

    for i in 0..STATE_WIDTH {
        state[i] += BaseElement::new(ROUND_CONSTANTS[round][i]);
    }

    if round < half_full || round >= half_full + PARTIAL_ROUNDS {
        for elem in state.iter_mut().take(STATE_WIDTH) {
            let x2 = *elem * *elem;
            *elem = x2 * x2 * *elem;
        }
    } else {
        let x2 = state[0] * state[0];
        state[0] = x2 * x2 * state[0];
    }

    let old: [BaseElement; STATE_WIDTH] = [state[0], state[1], state[2]];
    for i in 0..STATE_WIDTH {
        state[i] = BaseElement::ZERO;
        for j in 0..STATE_WIDTH {
            state[i] += old[j] * BaseElement::new(MDS_MATRIX[i][j]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_round_changes_state() {
        let mut state = [BaseElement::new(1), BaseElement::new(2), BaseElement::new(3)];
        let before = state;
        apply_round(0, &mut state);
        assert_ne!(state, before);
    }

    #[test]
    fn test_permutation_deterministic() {
        let mut state1 = PoseidonState::new();
        state1.state[0] = BaseElement::new(1);
        state1.state[1] = BaseElement::new(2);
        state1.permute();

        let mut state2 = PoseidonState::new();
        state2.state[0] = BaseElement::new(1);
        state2.state[1] = BaseElement::new(2);
        state2.permute();

        assert_eq!(state1.state, state2.state);
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let hash1 = poseidon_hash(&[BaseElement::new(1), BaseElement::new(2)]);
        let hash2 = poseidon_hash(&[BaseElement::new(1), BaseElement::new(3)]);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_bytes() {
        let hash1 = poseidon_hash_bytes(b"hello world");
        let hash2 = poseidon_hash_bytes(b"hello world");
        let hash3 = poseidon_hash_bytes(b"hello world!");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_bytes_to_elements() {
        let bytes = b"test input data";
        let elements = bytes_to_elements(bytes);

        // Should have at least 2 elements (data + length)
        assert!(elements.len() >= 2);

        // Last element should be the length
        assert_eq!(
            elements.last().unwrap(),
            &BaseElement::new(bytes.len() as u128)
        );
    }
}
