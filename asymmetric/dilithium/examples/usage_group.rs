use pqcrypto_dilithium::dilithium2::{detached_sign, keypair, verify_detached_signature};
use pqcrypto_traits::sign::DetachedSignature;
use sha2::{Digest, Sha256};

/// Hashes a single user identifier with SHA-256 to produce a Merkle leaf.
fn hash_leaf(user: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(user.as_bytes());
    hasher.finalize().to_vec()
}

/// Builds a binary Merkle tree from a list of user identifiers and returns the root hash.
///
/// Each leaf is the SHA-256 hash of the corresponding user string. Odd nodes are
/// promoted to the next level unchanged (duplicate-free construction).
fn build_merkle_root(users: &[&str]) -> Vec<u8> {
    let mut level: Vec<Vec<u8>> = users.iter().map(|u| hash_leaf(u)).collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() > 1 {
                hasher.update(&chunk[1]);
            }
            next.push(hasher.finalize().to_vec());
        }
        level = next;
    }
    level[0].clone()
}

/// Demonstrates group membership attestation using a Dilithium2 signature over a Merkle root.
///
/// An admin keypair is generated, a Merkle root is computed from the group member list,
/// and the root is signed by the admin. Any party holding the admin public key can then
/// verify that the root — and by extension the full member list — has not been tampered with.
///
/// # Panics
///
/// Panics if the detached signature cannot be verified against the Merkle root.
fn main() {
    let (admin_pub, admin_sec) = keypair();

    let users = vec!["Alice", "Bob", "Charlie", "David"];
    let root = build_merkle_root(&users);

    let sig = detached_sign(&root, &admin_sec);

    println!("Racine Merkle signée pour le groupe : {:x?}", root);
    println!("Signature (taille {} octets)", sig.as_bytes().len());

    let ok = verify_detached_signature(&sig, &root, &admin_pub).is_ok();
    println!("Signature valide ? {}", ok);
}
