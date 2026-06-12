pub mod serpent_cbc;
pub mod serpent_ctr;

pub use crate::serpent_cbc::{
    SerpentDecryptionError, SerpentEncryptionError, serpent_256_cbc_decrypt,
    serpent_256_cbc_encrypt,
};
