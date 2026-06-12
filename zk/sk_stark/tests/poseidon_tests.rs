use sk_stark::poseidon::{
    bytes_to_elements, poseidon_hash, poseidon_hash_bytes, poseidon_hash_two, PoseidonState,
};
use winterfell::math::fields::f128::BaseElement;
use winterfell::math::FieldElement;

// ── Determinism ──────────────────────────────────────────────────────────────

#[test]
fn hash_is_deterministic() {
    let input = [BaseElement::new(42), BaseElement::new(99)];
    assert_eq!(poseidon_hash(&input), poseidon_hash(&input));
}

#[test]
fn hash_bytes_is_deterministic() {
    let h1 = poseidon_hash_bytes(b"zenth_test_key");
    let h2 = poseidon_hash_bytes(b"zenth_test_key");
    assert_eq!(h1, h2);
}

#[test]
fn hash_two_is_deterministic() {
    let a = BaseElement::new(1);
    let b = BaseElement::new(2);
    assert_eq!(poseidon_hash_two(a, b), poseidon_hash_two(a, b));
}

// ── Collision resistance (basic) ──────────────────────────────────────────────

#[test]
fn different_inputs_produce_different_hashes() {
    let h1 = poseidon_hash(&[BaseElement::new(1)]);
    let h2 = poseidon_hash(&[BaseElement::new(2)]);
    assert_ne!(h1, h2);
}

#[test]
fn different_byte_inputs_produce_different_hashes() {
    assert_ne!(
        poseidon_hash_bytes(b"key_alice"),
        poseidon_hash_bytes(b"key_bob")
    );
}

#[test]
fn hash_two_not_commutative() {
    let a = BaseElement::new(10);
    let b = BaseElement::new(20);
    assert_ne!(poseidon_hash_two(a, b), poseidon_hash_two(b, a));
}

#[test]
fn domain_separation_works() {
    let input_a = b"same_secret_key_domain_A";
    let input_b = b"same_secret_key_domain_B";
    assert_ne!(poseidon_hash_bytes(input_a), poseidon_hash_bytes(input_b));
}

// ── bytes_to_elements ─────────────────────────────────────────────────────────

#[test]
fn empty_bytes_produces_length_element_only() {
    let elems = bytes_to_elements(b"");
    assert_eq!(elems.len(), 1);
    assert_eq!(elems[0], BaseElement::ZERO);
}

#[test]
fn length_element_is_appended() {
    let input = b"hello";
    let elems = bytes_to_elements(input);
    assert_eq!(
        *elems.last().unwrap(),
        BaseElement::new(input.len() as u128)
    );
}

#[test]
fn different_lengths_produce_different_elements() {
    let a = bytes_to_elements(b"abc");
    let b = bytes_to_elements(b"abcd");
    assert_ne!(a, b);
}

#[test]
fn large_input_is_chunked_correctly() {
    let input = vec![0xABu8; 100];
    let elems = bytes_to_elements(&input);
    // 100 bytes / 15 bytes per element = 7 chunks + 1 length element
    assert_eq!(elems.len(), 7 + 1);
    assert_eq!(*elems.last().unwrap(), BaseElement::new(100));
}

// ── PoseidonState sponge ──────────────────────────────────────────────────────

#[test]
fn absorb_then_squeeze_is_deterministic() {
    let input = [
        BaseElement::new(1),
        BaseElement::new(2),
        BaseElement::new(3),
    ];

    let mut s1 = PoseidonState::new();
    s1.absorb(&input);

    let mut s2 = PoseidonState::new();
    s2.absorb(&input);

    assert_eq!(s1.squeeze(), s2.squeeze());
}

#[test]
fn absorb_order_matters() {
    let a = BaseElement::new(1);
    let b = BaseElement::new(2);

    let mut s1 = PoseidonState::new();
    s1.absorb(&[a, b]);

    let mut s2 = PoseidonState::new();
    s2.absorb(&[b, a]);

    assert_ne!(s1.squeeze(), s2.squeeze());
}

#[test]
fn squeeze_many_returns_correct_count() {
    let mut state = PoseidonState::new();
    state.absorb(&[BaseElement::new(7)]);
    let output = state.squeeze_many(4);
    assert_eq!(output.len(), 4);
}

#[test]
fn permute_changes_state() {
    let mut state = PoseidonState::new();
    let before = *state.state();
    state.permute();
    assert_ne!(*state.state(), before);
}

#[test]
fn from_state_preserves_values() {
    let values = [
        BaseElement::new(11),
        BaseElement::new(22),
        BaseElement::new(33),
    ];
    let state = PoseidonState::from_state(values);
    assert_eq!(*state.state(), values);
}

// ── hash_two consistency with hash ────────────────────────────────────────────

#[test]
fn hash_two_consistent_with_hash() {
    let a = BaseElement::new(5);
    let b = BaseElement::new(6);

    // hash_two sets state directly and permutes once
    let via_two = poseidon_hash_two(a, b);

    // absorb on a fresh state with [a, b] should produce same result
    let mut state = PoseidonState::new();
    state.absorb(&[a, b]);
    let via_absorb = state.squeeze();

    // Both go through a single permutation with the same initial state
    assert_eq!(via_two, via_absorb);
}
