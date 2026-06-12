//! Key exchange primitives: ECDH (Curve25519/X25519), HPKE, and SPAKE2 PAKE.
//!
//! | Module            | Protocol          | Purpose                                          |
//! |-------------------|-------------------|--------------------------------------------------|
//! | [`curve`]         | X25519 / XEdDSA   | High-level keypair, signing, ECDH agreement      |
//! | [`curve25519`]    | X25519 / XEdDSA   | Low-level Curve25519 primitives                  |
//! | [`hybrid`]        | HPKE (RFC 9180)   | Hybrid public-key encryption crypto provider     |
//! | [`spake2_wrapper`]| SPAKE2 (IETF)     | Password-authenticated key exchange              |

pub mod curve;
pub mod curve25519;
pub mod diffie_hellman;
pub mod hybrid;
pub mod spake2_wrapper;
