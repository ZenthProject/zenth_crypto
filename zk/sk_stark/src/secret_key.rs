//! Secret Key STARK — Zero-Knowledge Proof of Secret Key Knowledge.
//!
//! Proves knowledge of a secret key without revealing it:
//! "I know `sk` such that `Poseidon(sk || domain) = commitment`"
//!
//! Security properties:
//! - Zero-knowledge: verifier learns nothing about the secret key
//! - Soundness: cannot forge a proof without knowing the key
//! - Post-quantum: based on hash functions (STARK + Poseidon)

use serde::{Deserialize, Serialize};
use winterfell::{
    math::fields::f128::BaseElement,
    math::{FieldElement, StarkField},
    Air, AirContext, Assertion, ByteReader, ByteWriter, DeserializationError, EvaluationFrame,
    FieldExtension, HashFunction, ProofOptions, Prover, Serializable, StarkProof, TraceInfo,
    TraceTable, TransitionConstraintDegree,
};

use crate::poseidon::{
    apply_round, bytes_to_elements, PoseidonState, FULL_ROUNDS, MDS_MATRIX, PARTIAL_ROUNDS,
    ROUND_CONSTANTS, STATE_WIDTH,
};

const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
const TRACE_WIDTH: usize = STATE_WIDTH;

// ── Shared helpers ────────────────────────────────────────────────────────────

fn bytes16_to_element(bytes: &[u8; 16]) -> BaseElement {
    let mut value: u128 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        value |= (byte as u128) << (i * 8);
    }
    BaseElement::new(value)
}

fn element_to_bytes16(elem: BaseElement) -> [u8; 16] {
    let value = elem.as_int();
    let mut result = [0u8; 16];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = ((value >> (i * 8)) & 0xFF) as u8;
    }
    result
}

/// Builds the initial Poseidon state from key elements and domain.
///
/// Uses the first two key elements as rate inputs and domain as capacity.
fn initial_state(key: &[BaseElement], domain: BaseElement) -> PoseidonState {
    PoseidonState::from_state([
        key.first().copied().unwrap_or(BaseElement::ZERO),
        key.get(1).copied().unwrap_or(BaseElement::ZERO),
        domain,
    ])
}

// ── Public inputs ─────────────────────────────────────────────────────────────

/// Public inputs for the SK-STARK: commitment and domain separator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKeyPublicInputs {
    /// Poseidon commitment of the secret key
    pub commitment: [u8; 16],
    /// Domain separator to prevent cross-context replay
    pub domain: [u8; 16],
}

impl SecretKeyPublicInputs {
    /// Commitment as a field element.
    pub fn commitment_element(&self) -> BaseElement {
        bytes16_to_element(&self.commitment)
    }

    /// Domain as a field element.
    pub fn domain_element(&self) -> BaseElement {
        bytes16_to_element(&self.domain)
    }
}

impl Serializable for SecretKeyPublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.commitment);
        target.write_u8_slice(&self.domain);
    }
}

impl winterfell::Deserializable for SecretKeyPublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut commitment = [0u8; 16];
        let mut domain = [0u8; 16];
        for byte in &mut commitment {
            *byte = source.read_u8()?;
        }
        for byte in &mut domain {
            *byte = source.read_u8()?;
        }
        Ok(Self { commitment, domain })
    }
}

// ── AIR ───────────────────────────────────────────────────────────────────────

/// AIR for SK-STARK.
///
/// Proves that the execution trace correctly computes
/// `Poseidon(secret_key || domain) = commitment`.
pub struct SecretKeyAir {
    context: AirContext<BaseElement>,
    commitment: BaseElement,
    domain: BaseElement,
}

impl Air for SecretKeyAir {
    type BaseField = BaseElement;
    type PublicInputs = SecretKeyPublicInputs;

    /// The dominant constraint term is `is_active * is_partial * arc^5`:
    /// - Trace degree 5 from `(T + rc)^5`
    /// - 2 periodic columns: `is_active` and `is_partial` (cycle = trace length)
    ///
    /// Evaluation degree = `7*(n-1)`. `with_cycles(5, [n, n])` sizes the CE domain correctly.
    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let n = trace_info.length();
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![n, n]),
            TransitionConstraintDegree::with_cycles(5, vec![n, n]),
            TransitionConstraintDegree::with_cycles(5, vec![n, n]),
        ];
        let context = AirContext::new(trace_info, degrees, 2, options);
        Self {
            context,
            commitment: pub_inputs.commitment_element(),
            domain: pub_inputs.domain_element(),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// Periodic columns (one value per trace step):
    /// - `[0..2]`: round constants `RC[s][0..2]`
    /// - `[3]`: `is_partial` — `1` for partial rounds, `0` for full rounds
    /// - `[4]`: `is_active`  — `1` for steps `0..TOTAL_ROUNDS-1`, `0` after
    fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
        let trace_len = self.trace_length();
        let mut rc0 = vec![BaseElement::ZERO; trace_len];
        let mut rc1 = vec![BaseElement::ZERO; trace_len];
        let mut rc2 = vec![BaseElement::ZERO; trace_len];
        let mut is_partial = vec![BaseElement::ZERO; trace_len];
        let mut is_active = vec![BaseElement::ZERO; trace_len];

        let half_full = FULL_ROUNDS / 2;
        for s in 0..TOTAL_ROUNDS {
            rc0[s] = BaseElement::new(ROUND_CONSTANTS[s][0]);
            rc1[s] = BaseElement::new(ROUND_CONSTANTS[s][1]);
            rc2[s] = BaseElement::new(ROUND_CONSTANTS[s][2]);
            if s >= half_full && s < half_full + PARTIAL_ROUNDS {
                is_partial[s] = BaseElement::ONE;
            }
            is_active[s] = BaseElement::ONE;
        }

        vec![rc0, rc1, rc2, is_partial, is_active]
    }

    fn evaluate_transition<E: winterfell::math::FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let rc = [periodic_values[0], periodic_values[1], periodic_values[2]];
        let is_partial = periodic_values[3];
        let is_full = E::ONE - is_partial;
        let is_active = periodic_values[4];
        let is_inactive = E::ONE - is_active;

        let arc = [current[0] + rc[0], current[1] + rc[1], current[2] + rc[2]];

        let sbox0 = {
            let x2 = arc[0] * arc[0];
            x2 * x2 * arc[0]
        };
        let sbox = [
            sbox0,
            {
                let x2 = arc[1] * arc[1];
                let x5 = x2 * x2 * arc[1];
                is_full * x5 + is_partial * arc[1]
            },
            {
                let x2 = arc[2] * arc[2];
                let x5 = x2 * x2 * arc[2];
                is_full * x5 + is_partial * arc[2]
            },
        ];

        #[allow(clippy::needless_range_loop)]
        for i in 0..STATE_WIDTH {
            let mut mds_out = E::ZERO;
            for j in 0..STATE_WIDTH {
                mds_out += sbox[j] * E::from(BaseElement::new(MDS_MATRIX[i][j]));
            }
            result[i] = is_active * (next[i] - mds_out) + is_inactive * (next[i] - current[i]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(2, 0, self.domain),
            Assertion::single(0, last_step, self.commitment),
        ]
    }
}

// ── Prover ────────────────────────────────────────────────────────────────────

/// STARK prover for secret key knowledge.
pub struct SecretKeyProver {
    options: ProofOptions,
    secret_key: Vec<BaseElement>,
    domain: BaseElement,
}

impl SecretKeyProver {
    /// Creates a new prover for the given secret key and domain separator.
    pub fn new(secret_key_bytes: &[u8], domain: &[u8; 16]) -> Self {
        Self {
            options: Self::default_options(),
            secret_key: bytes_to_elements(secret_key_bytes),
            domain: bytes16_to_element(domain),
        }
    }

    /// Default proof options: 64 queries (≈128-bit security), 16× blowup, Blake3-256.
    pub fn default_options() -> ProofOptions {
        ProofOptions::new(
            64,
            16,
            0,
            HashFunction::Blake3_256,
            FieldExtension::None,
            8,
            256,
        )
    }

    /// Computes `Poseidon([key[0], key[1], domain])` — the public commitment.
    pub fn compute_commitment(&self) -> BaseElement {
        let mut state = initial_state(&self.secret_key, self.domain);
        state.permute();
        state.squeeze()
    }

    /// Builds the execution trace for the Poseidon computation.
    fn build_trace(&self) -> TraceTable<BaseElement> {
        let trace_length = (TOTAL_ROUNDS + 2).next_power_of_two().max(8);
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        let init = initial_state(&self.secret_key, self.domain);
        let state: [BaseElement; STATE_WIDTH] = *init.state();

        trace.fill(
            |row_state| {
                row_state[..STATE_WIDTH].copy_from_slice(&state[..STATE_WIDTH]);
            },
            |step, row_state| {
                if step < TOTAL_ROUNDS {
                    apply_round(step, row_state);
                }
            },
        );

        trace
    }
}

impl Prover for SecretKeyProver {
    type BaseField = BaseElement;
    type Air = SecretKeyAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SecretKeyPublicInputs {
        SecretKeyPublicInputs {
            commitment: element_to_bytes16(self.compute_commitment()),
            domain: element_to_bytes16(self.domain),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Serialized SK-STARK proof with its public inputs.
#[derive(Serialize, Deserialize)]
pub struct SecretKeyProof {
    /// The serialized STARK proof bytes
    pub proof_bytes: Vec<u8>,
    /// Public inputs (commitment + domain)
    pub public_inputs: SecretKeyPublicInputs,
}

/// Errors returned by SK-STARK operations.
#[derive(Debug, Clone)]
pub enum SecretKeyError {
    /// Proof generation failed
    ProofGenerationFailed(String),
    /// Proof verification failed
    VerificationFailed(String),
    /// Invalid secret key provided
    InvalidSecretKey(String),
    /// Proof serialization or deserialization failed
    SerializationError(String),
}

impl std::fmt::Display for SecretKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretKeyError::ProofGenerationFailed(msg) => {
                write!(f, "Proof generation failed: {}", msg)
            }
            SecretKeyError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            SecretKeyError::InvalidSecretKey(msg) => write!(f, "Invalid secret key: {}", msg),
            SecretKeyError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for SecretKeyError {}

/// Generates a SK-STARK proof of knowledge of `secret_key`.
///
/// # Arguments
/// * `secret_key` — the secret key bytes
/// * `domain` — 16-byte domain separator (prevents cross-context replay)
///
/// # Errors
/// Returns [`SecretKeyError`] if `secret_key` is empty or proof generation fails.
pub fn prove_secret_key(
    secret_key: &[u8],
    domain: &[u8; 16],
) -> Result<SecretKeyProof, SecretKeyError> {
    if secret_key.is_empty() {
        return Err(SecretKeyError::InvalidSecretKey(
            "secret key cannot be empty".to_string(),
        ));
    }

    let prover = SecretKeyProver::new(secret_key, domain);
    let trace = prover.build_trace();
    let public_inputs = prover.get_pub_inputs(&trace);

    let proof_bytes = prover
        .prove(trace)
        .map_err(|e| SecretKeyError::ProofGenerationFailed(e.to_string()))?
        .to_bytes();

    Ok(SecretKeyProof {
        proof_bytes,
        public_inputs,
    })
}

/// Computes the 16-byte Poseidon commitment for `secret_key` under `domain`.
///
/// Store this value to verify proofs later without retaining the secret key.
pub fn compute_commitment(secret_key: &[u8], domain: &[u8; 16]) -> [u8; 16] {
    let prover = SecretKeyProver::new(secret_key, domain);
    element_to_bytes16(prover.compute_commitment())
}

/// Verifies a SK-STARK proof.
///
/// If `expected_commitment` is provided, the proof's commitment must match it exactly.
///
/// # Errors
/// Returns [`SecretKeyError`] if the commitment mismatches or the STARK proof is invalid.
pub fn verify_secret_key(
    proof: &SecretKeyProof,
    expected_commitment: Option<&[u8; 16]>,
) -> Result<(), SecretKeyError> {
    if let Some(expected) = expected_commitment {
        if &proof.public_inputs.commitment != expected {
            return Err(SecretKeyError::VerificationFailed(
                "commitment mismatch".to_string(),
            ));
        }
    }

    let stark_proof = StarkProof::from_bytes(&proof.proof_bytes)
        .map_err(|e| SecretKeyError::SerializationError(e.to_string()))?;

    winterfell::verify::<SecretKeyAir>(stark_proof, proof.public_inputs.clone())
        .map_err(|e| SecretKeyError::VerificationFailed(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_deterministic() {
        let secret = b"test_secret_key_12345";
        let domain = b"zenth_test_v1\0\0\0";
        assert_eq!(
            compute_commitment(secret, domain),
            compute_commitment(secret, domain)
        );
    }

    #[test]
    fn test_different_secrets_different_commitments() {
        let domain = b"zenth_test_v1\0\0\0";
        assert_ne!(
            compute_commitment(b"secret_1", domain),
            compute_commitment(b"secret_2", domain)
        );
    }

    #[test]
    fn test_different_domains_different_commitments() {
        let secret = b"same_secret_key";
        assert_ne!(
            compute_commitment(secret, b"domain_1\0\0\0\0\0\0\0\0"),
            compute_commitment(secret, b"domain_2\0\0\0\0\0\0\0\0")
        );
    }

    #[test]
    fn test_prover_commitment_nonzero() {
        let prover = SecretKeyProver::new(b"test_secret", b"test_domain_v1\0\0");
        assert_ne!(prover.compute_commitment(), BaseElement::ZERO);
    }

    #[test]
    fn test_compute_commitment_matches_prover() {
        let secret = b"consistency_check";
        let domain = b"zenth_test_v1\0\0\0";
        let prover = SecretKeyProver::new(secret, domain);
        assert_eq!(
            compute_commitment(secret, domain),
            element_to_bytes16(prover.compute_commitment())
        );
    }

    #[test]
    #[ignore]
    fn test_prove_and_verify() {
        let secret = b"this_is_my_secret_key_for_testing";
        let domain = b"zenth_auth_v1\0\0\0";

        let proof = prove_secret_key(secret, domain).expect("proof generation failed");
        verify_secret_key(&proof, None).expect("verification failed");

        let commitment = compute_commitment(secret, domain);
        verify_secret_key(&proof, Some(&commitment)).expect("verification with commitment failed");
    }
}
