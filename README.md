# zenth_crypto

Workspace de cryptographie Rust pour le projet Zenth. Regroupe l'ensemble des primitives cryptographiques utilisées dans le projet : chiffrement symétrique, asymétrique, post-quantique, échange de clés, dérivation, protocoles de messagerie et preuves à divulgation nulle.

## Prérequis

- Rust 1.85+ (edition 2024)
- `cmake` et `clang` (requis par BoringSSL via `boring-sys`)

## Build & tests

```sh
cargo build --workspace
cargo test --workspace

# Le test ZK complet est ignoré par défaut (lourd) :
cargo test -p sk_stark --release -- --ignored
```

## Structure du workspace

| Crate | Description |
|---|---|
| `encoding` | Encodage Base64, hex et PEM avec zeroisation automatique |
| `hashing` | SHA-2, SHA-3, BLAKE2, HMAC |
| `kdf` | HKDF-SHA256/384/512, Argon2id, utilitaires de dérivation |
| `exchange` | X25519, XEdDSA, SPAKE2, HPKE |
| `kem` | Kyber768, Kyber1024, ML-KEM 1024 (FIPS 203) |
| `symmetric` | AES-GCM, ChaCha20-Poly1305, Serpent, Twofish |
| `asymmetric` | RSA-OAEP 4096, Dilithium3 (ML-DSA), LMS |
| `protocols` | Double Ratchet, X3DH, PQXDH |
| `utils` | Comparaison en temps constant |
| `zk/sk_stark` | Preuve à divulgation nulle de connaissance d'une clé secrète (Poseidon + STARK) |

## Utilisation

Chaque crate est indépendante et peut être importée individuellement via son chemin dans `Cargo.toml`. Les doc-comments de chaque crate (`cargo doc --open`) décrivent les types, erreurs et le comportement attendu. Des exemples exécutables sont disponibles dans les dossiers `examples/` de certaines crates.

```sh
cargo doc --open
```

## Notes de sécurité

- **LMS** est un schéma de signature à état. L'état de la clé privée doit être persisté entre les redémarrages pour éviter toute réutilisation.
- **SK-STARK** utilise des constantes Poseidon générées de façon déterministe. À remplacer par des constantes issues du Grain LFSR pour un usage en production.
- L'état de session sérialisé (`protocols`) contient des clés sensibles — chiffrer avant stockage.

## Licence

AGPL-3.0. Les fichiers dérivés de libsignal conservent leur licence d'origine (AGPL-3.0).
