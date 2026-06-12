# Workspace Cleanup Checklist

---

## 1. Commentaires inline dans les fonctions

### Règle
Aucun commentaire `//` à l'intérieur d'un corps de fonction.
- `//!` en tête de fichier : documenter le module — autorisé et obligatoire.
- `///` sur un item (fn, struct, const…) : doc-comment — autorisé et obligatoire sur le public.
- `//` à l'intérieur d'une fonction : interdit. Un bon nom de variable ou de fonction
  remplace toujours un commentaire.

**Exceptions légales uniquement** :
- `// SAFETY: …` avant un bloc `unsafe`
- `// FIXME: …` ou `// TODO: …` temporaires avec un ticket référencé
- Workaround explicite pour un bug de crate externe

### Avant / Après

```rust
// AVANT — keys.rs
pub fn derive(ikm: &[u8], salt: Option<&[u8]>, counter: u32) -> Self {
    // Derive 80 bytes: 32 (cipher) + 32 (mac) + 16 (iv)
    let (cipher_key, mac_key, iv) = derive_arrays(|okm| { … });
}

// APRÈS — les noms suffisent
pub fn derive(ikm: &[u8], salt: Option<&[u8]>, counter: u32) -> Self {
    let (cipher_key, mac_key, iv) = derive_arrays(|okm| { … });
}
```

```rust
// AVANT — un commentaire remplace un mauvais nom de test
// Same inputs should produce same output
assert_eq!(result1, result2);

// APRÈS — le nom du test est le commentaire
#[test]
fn same_inputs_produce_same_output() {
    assert_eq!(result1, result2);
}
```

```rust
// AVANT — arrays.rs (transmute sans explication légale)
// Transmute [u8] to [[u8; 16]], like slice::as_chunks.
unsafe { std::mem::transmute(slice) }

// APRÈS — SAFETY obligatoire, explication concise
// SAFETY: [u8; N*16] et [[u8; 16]; N] ont le même layout (repr(C) identique).
unsafe { std::mem::transmute(slice) }
```

### Fichiers concernés (111 commentaires au total)

| Crate | Fichiers |
|---|---|
| `kdf` | `argon2id.rs`, `hkdf.rs`, `crypto.rs`, `arrays.rs` |
| `encoding` | `base64.rs`, `hex.rs`, `pem.rs` |
| `hashing` | `hash.rs` |
| `exchange` | `curve25519.rs`, `hybrid.rs`, `spake2_wrapper.rs`, `curve.rs` |
| `symmetric/aes_modes` | `aes_cbc.rs`, `aes_gcm.rs` |
| `symmetric/serpent_modes` | `serpent_cbc.rs` |
| `symmetric/twofish_modes` | `twofish_cbc.rs` |
| `asymmetric/dilithium` | `dilithium.rs` |
| `asymmetric/rsa_oaep` | `rsa4096.rs` |
| `asymmetric/lms` | `lms.rs` |
| `errors` | `error.rs` |
| `kem` | `lib.rs` |
| `protocols` | `keys.rs`, `state.rs`, `cipher.rs`, `pqxdh.rs` |
| `protocols/x3dh` | `agreement.rs`, `bundle.rs`, `keys.rs` |
| `protocols/hpke` | `provider.rs` |
| `zk/sk_stark` | `poseidon.rs`, `secret_key.rs` |
| `src/lib.rs` (racine) | commentaires de section `// Core utilities…` etc. |

---

## 2. Doc-comments manquants (`//!` sur les modules)

### Règle
Chaque `lib.rs` doit commencer par un bloc `//!` décrivant la crate :
ce qu'elle expose, dans quel contexte l'utiliser, et les modules principaux.
Sans ça, `cargo doc` génère une page vide pour la crate.

### Fichiers sans `//!`

| Fichier | Statut |
|---|---|
| `errors/src/lib.rs` | Vide — juste `pub mod error;` |
| `protocols/hpke/src/lib.rs` | Vide — juste `pub mod provider; pub use …` |
| `symmetric/aes_modes/src/lib.rs` | Vide — juste les `pub mod` et `pub use` |
| `symmetric/serpent_modes/src/lib.rs` | À vérifier |
| `symmetric/twofish_modes/src/lib.rs` | À vérifier |
| `asymmetric/src/lib.rs` | À vérifier |
| `src/lib.rs` (racine) | A des `//` de section au lieu de `//!` |

### Exemple

```rust
// AVANT — errors/src/lib.rs
pub mod error;

// APRÈS
//! Error types shared across the workspace.
//!
//! All crates in this workspace return [`error::Error`] or a crate-local
//! enum that wraps it. Import this crate to match on error variants.
pub mod error;
```

---

## 3. `.unwrap()` et `.expect()` en code de production

### Règle
`.unwrap()` et `.expect()` sont acceptables **uniquement dans les tests** et les
**exemples**. Dans le code de production (tout ce qui n'est pas `#[cfg(test)]`
ni `examples/`), ils doivent être remplacés par une propagation d'erreur (`?`)
ou une gestion explicite.

`.expect("message")` avec un message explicatif est toléré **seulement si
l'invariant est garanti statiquement** et ne peut pas échouer à l'exécution
(ex. : `Hmac::new_from_slice` accepte n'importe quelle longueur de clé).
Dans ce cas, le message doit expliquer *pourquoi* c'est impossible, pas juste
redire ce qu'on fait.

### Avant / Après

```rust
// AVANT — rsa4096.rs : panic déguisé en production
.unwrap_or_else(|_| panic!("RSA-4096 OAEP decryption failed"))

// APRÈS — retourner une erreur typée
.map_err(|_| RsaError::DecryptionFailed)?
```

```rust
// AVANT — hashing/hash.rs : expect sans justification
Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length")

// ACCEPTABLE (invariant statique documenté) — le message explique POURQUOI
Hmac::<Sha256>::new_from_slice(key)
    .expect("new_from_slice never fails: HMAC accepts keys of any length per RFC 2104")
```

### Fichiers concernés (164 occurrences)

Priorité : tout ce qui est hors tests et hors `examples/` — commencer par
`rsa4096.rs` (seul vrai `panic!` en production) puis balayer `hashing/`, `kdf/`,
`symmetric/`, `exchange/`.

---

## 4. `#[allow(…)]` à investiguer

### Règle
Un `#[allow]` qui supprime un avertissement sans commentaire `// SAFETY` ou
`// FIXME` est de la dette cachée. Chaque `#[allow]` doit être soit :
- justifié par un commentaire expliquant pourquoi c'est inévitable, ou
- remplacé par du code qui n'en a plus besoin.

### Occurrences actuelles

| Fichier | Attribut | Action |
|---|---|---|
| `aes_gcm.rs` | `#![allow(deprecated)]` | Migrer vers l'API non-deprecated de `generic-array` ou ajouter un commentaire de version cible |
| `chacha.rs` | `#![allow(deprecated)]` | Idem |
| `protocols/state.rs` | `#![allow(unused_assignments)]` | Investiguer : variable assignée mais jamais lue = potentiel bug logique |
| `protocols/x3dh/keys.rs` | `#![allow(unused_assignments)]` | Idem |
| `kdf/arrays.rs` | `#[allow(clippy::type_complexity)]` | Acceptable si type alias trop verbeux — ajouter un commentaire |

`unused_assignments` est particulièrement suspect : Rust l'émet quand une valeur
est écrasée avant d'avoir été lue, ce qui peut indiquer une logique incorrecte.

---

## 5. Tests manquants

### Règle
Chaque crate doit avoir au minimum :
- Tests unitaires dans les sources (`#[cfg(test)] mod tests`) pour les fonctions non-triviales.
- Un fichier d'intégration dans `tests/` couvrant le chemin principal depuis l'extérieur.

Les quatre propriétés à couvrir en priorité :
1. **Déterminisme** — même entrée → même sortie
2. **Collision basique** — entrées différentes → sorties différentes
3. **Chemin d'erreur** — les erreurs attendues sont bien retournées
4. **Round-trip** — encode/decode, chiffre/déchiffre, signe/vérifie

### Nommage des tests

Le nom du test doit se lire comme une phrase :

```rust
// MAUVAIS
#[test] fn test1() { … }
#[test] fn test_hash() { … }

// BIEN
#[test] fn sha256_same_input_same_digest() { … }
#[test] fn argon2_wrong_password_returns_error() { … }
#[test] fn base64_roundtrip_preserves_bytes() { … }
```

### Tests lents : utiliser `#[ignore]` avec message

```rust
// MAUVAIS
#[test]
#[ignore]
fn test_prove_and_verify() { … }

// BIEN
#[test]
#[ignore = "slow: ~1s STARK proof generation, run with --include-ignored"]
fn prove_and_verify_roundtrip() { … }
```

### Crates sans couverture suffisante

| Crate | Tests actuels | Manque |
|---|---|---|
| `encoding` | 0 dans les sources | déterminisme base64/hex/pem, round-trip, cas d'erreur |
| `errors` | 0 | Display des variants, conversion depuis autres erreurs |
| `kdf` | 1 (argon seul) | hkdf déterminisme, extract/expand séparé, arrays derive |
| `hashing` | 0 | sha2/sha3/hmac déterminisme, longueur sortie, cas d'erreur |
| `kem` | 0 | encapsulate/decapsulate round-trip, mauvaise clé rejette |
| `symmetric/serpent_modes` | intégration seul | unitaires dans serpent_cbc/ctr |
| `symmetric/twofish_modes` | intégration seul | unitaires dans twofish_cbc/ctr |
| `asymmetric/lms` | 0 | sign/verify round-trip, exhausted key error |
| `protocols/hpke` | 0 | seal/open round-trip, mauvaise clé rejette |
| `exchange` | 1 (ecdh) | spake2 round-trip, hybrid déterminisme |
| `zk/sk_stark` | poseidon seul | `tests/secret_key_tests.rs` : prove/verify, commitment |

---

## 6. Dépendances inutilisées

`zk/sk_stark/Cargo.toml` déclare `rand = "0.8"` mais le code ne l'importe pas.

```toml
# AVANT
[dependencies]
serde = { version = "1.0", features = ["derive"] }
rand = "0.8"
winterfell = "0.4"

# APRÈS
[dependencies]
serde = { version = "1.0", features = ["derive"] }
winterfell = "0.4"
```

---

## 7. Incohérence d'édition Rust

Toutes les crates devraient utiliser `edition = "2024"`.

| Crate | Valeur actuelle |
|---|---|
| `protocols` | `edition = "2021"` |
| `asymmetric/lms` | `edition = "2021"` |
| `zk/sk_stark` | `edition = "2021"` |

Après le changement : `cargo check -p <crate>` pour valider (edition 2024 modifie
la capture des closures et certaines règles `use`).

---

## 8. Fragmentation des versions de `rand`

Deux versions coexistent, ce qui double le temps de compilation.

| Version | Crates |
|---|---|
| `rand 0.8` | `kdf`, `protocols`, `rsa_oaep`, `lms` |
| `rand 0.9` | `utils`, `twofish_modes`, `kem`, `exchange` |

`protocols` a même un alias `rand09 = { package = "rand", version = "0.9" }` pour
gérer les deux simultanément.

**Action** : migrer les crates en 0.8 vers 0.9, puis supprimer l'alias `rand09`.
Changements types : `rand::thread_rng()` → `rand::rng()`, `Rng::gen()` → `Rng::random()`.

---

## 9. `protocols/hpke` absent des dépendances racine

`hpke` est dans `[workspace].members` mais pas dans les `[dependencies]` de la
crate racine `zenth_crypto`. Soit l'ajouter, soit documenter pourquoi il est
intentionnellement interne.

```toml
# Option A : l'exposer comme les autres crates
hpke = { path = "protocols/hpke" }

# Option B : garder interne — ajouter un commentaire dans Cargo.toml
# hpke est volontairement non-exposé : dépendance interne de `protocols` uniquement.
```

---

## Ordre de traitement recommandé

| # | Tâche | Effort | Risque |
|---|---|---|---|
| 1 | `rand` inutilisé dans `sk_stark` | 1 min | nul |
| 2 | Aligner les 3 éditions sur 2024 | 10 min | faible |
| 3 | `//!` manquants sur les `lib.rs` vides | 20 min | nul |
| 4 | Investiguer `#[allow(unused_assignments)]` | 30 min | potentiel bug |
| 5 | Inline comments — fichier par fichier | 2-3h | faible |
| 6 | Clarifier `hpke` dans le workspace root | 5 min | nul |
| 7 | `panic!` en production → erreur typée | 1h | modéré |
| 8 | Tests manquants | 1-2 jours | nul |
| 9 | Migration `rand 0.8 → 0.9` | 1h | modéré |
