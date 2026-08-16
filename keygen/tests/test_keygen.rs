// kdf/tests/test_password_derivation.rs
//
// Tests pour derive_keys_from_password et derive_keys_from_password_with_salt.
// Adapte le `use` ci-dessous selon l'emplacement réel des fonctions dans le crate `kdf`.

use keygen::{derive_keys_from_password, derive_keys_from_password_with_salt};

/// La clé dérivée doit toujours faire 32 octets (paramètre demandé explicitement),
/// et le salt généré ne doit jamais être vide.
#[test]
fn test_output_length() {
    let (key, salt) = derive_keys_from_password("correct horse battery staple")
        .expect("derivation should succeed");

    assert_eq!(key.len(), 32, "la clé dérivée doit faire exactement 32 octets");
    assert!(!salt.is_empty(), "le salt généré ne doit jamais être vide");
}

/// Avec le même mot de passe et le même salt, la dérivation doit être
/// parfaitement reproductible (propriété fondamentale d'Argon2id).
#[test]
fn test_deterministic_with_same_salt() {
    let password = "correct horse battery staple";
    let salt = b"a-fixed-test-salt-16b";

    let hash1 = derive_keys_from_password_with_salt(password, salt)
        .expect("first derivation should succeed");
    let hash2 = derive_keys_from_password_with_salt(password, salt)
        .expect("second derivation should succeed");

    assert_eq!(hash1, hash2, "même password + même salt doit produire la même clé");
}

/// Un salt différent doit produire une clé différente, même avec le même mot de passe.
#[test]
fn test_different_salt_different_hash() {
    let password = "correct horse battery staple";
    let salt_a = b"salt-value-number-one";
    let salt_b = b"salt-value-number-two";

    let hash_a = derive_keys_from_password_with_salt(password, salt_a)
        .expect("derivation with salt_a should succeed");
    let hash_b = derive_keys_from_password_with_salt(password, salt_b)
        .expect("derivation with salt_b should succeed");

    assert_ne!(hash_a, hash_b, "des salts différents doivent produire des clés différentes");
}

/// Un mot de passe différent doit produire une clé différente, même avec le même salt.
#[test]
fn test_different_password_different_hash() {
    let salt = b"a-fixed-test-salt-16b";

    let hash_a = derive_keys_from_password_with_salt("password-one", salt)
        .expect("derivation for password-one should succeed");
    let hash_b = derive_keys_from_password_with_salt("password-two", salt)
        .expect("derivation for password-two should succeed");

    assert_ne!(hash_a, hash_b, "des mots de passe différents doivent produire des clés différentes");
}

/// Deux appels successifs à derive_keys_from_password (qui génère son propre salt
/// aléatoirement) doivent produire des salts ET des clés différentes.
/// Sinon la génération de salt n'est pas vraiment aléatoire — faille de sécurité critique.
#[test]
fn test_random_salt_each_call_produces_different_output() {
    let password = "correct horse battery staple";

    let (key1, salt1) = derive_keys_from_password(password)
        .expect("first call should succeed");
    let (key2, salt2) = derive_keys_from_password(password)
        .expect("second call should succeed");

    assert_ne!(salt1, salt2, "chaque appel doit générer un salt distinct");
    assert_ne!(key1, key2, "des salts distincts doivent produire des clés distinctes");
}

/// Le salt renvoyé par derive_keys_from_password doit, une fois réinjecté dans
/// derive_keys_from_password_with_salt, reproduire exactement la même clé.
/// C'est la garantie qu'on peut stocker le salt et reproduire la dérivation au login.
#[test]
fn test_roundtrip_consistency_between_both_functions() {
    let password = "correct horse battery staple";

    let (original_key, salt) = derive_keys_from_password(password)
        .expect("initial derivation should succeed");

    let reproduced_key = derive_keys_from_password_with_salt(password, &salt)
        .expect("reproduction with stored salt should succeed");

    assert_eq!(
        original_key, reproduced_key,
        "réutiliser le salt stocké doit reproduire exactement la même clé (cas du login)"
    );
}

/// Un mot de passe vide ne doit pas paniquer — Argon2id reste défini pour une
/// entrée vide, même si ce n'est pas un cas d'usage recommandé côté produit.
#[test]
fn test_empty_password_does_not_panic() {
    let salt = b"a-fixed-test-salt-16b";
    let result = derive_keys_from_password_with_salt("", salt);
    assert!(result.is_ok(), "un mot de passe vide ne doit pas faire échouer la dérivation");
}

/// Un mot de passe contenant de l'UTF-8 non-ASCII (accents, emoji) doit être
/// géré correctement sans panique ni troncature silencieuse.
#[test]
fn test_unicode_password() {
    let salt = b"a-fixed-test-salt-16b";
    let password = "correct chevalöß battérie 🔒 agrafé";

    let result = derive_keys_from_password_with_salt(password, salt);
    assert!(result.is_ok(), "un mot de passe unicode doit être accepté");

    // Doit rester déterministe comme n'importe quel autre mot de passe.
    let hash1 = derive_keys_from_password_with_salt(password, salt).unwrap();
    let hash2 = derive_keys_from_password_with_salt(password, salt).unwrap();
    assert_eq!(hash1, hash2);
}

/// Un salt très court (en dessous de ce qu'Argon2 recommande, 8 octets min RFC 9106)
/// doit soit être rejeté proprement, soit fonctionner sans paniquer.
/// Ce test documente le comportement actuel plutôt que d'imposer un choix.
#[test]
fn test_short_salt_does_not_panic() {
    let short_salt = b"ab"; // 2 octets, en dessous du minimum recommandé
    let result = derive_keys_from_password_with_salt("some-password", short_salt);
    // On ne force pas Ok ou Err ici : l'important est l'absence de panique.
    // Si la lib sous-jacente rejette les salts trop courts, ce test documente
    // ce choix ; si elle les accepte, il documente aussi ce choix.
    match result {
        Ok(key) => assert_eq!(key.len(), 32, "si accepté, la longueur de sortie doit rester 32 octets"),
        Err(_) => {} // rejet propre acceptable
    }
}

/// Un salt vide est un cas dégénéré qui doit être rejeté ou géré sans paniquer.
#[test]
fn test_empty_salt_does_not_panic() {
    let empty_salt: &[u8] = b"";
    let result = derive_keys_from_password_with_salt("some-password", empty_salt);
    match result {
        Ok(key) => assert_eq!(key.len(), 32),
        Err(_) => {} // rejet propre acceptable pour un salt vide
    }
}

/// Vérifie que la clé dérivée n'est pas triviale (pas tout à zéro, pas un pattern
/// évident) — garde-fou grossier contre une implémentation cassée qui renverrait
/// un buffer non initialisé.
#[test]
fn test_derived_key_is_not_trivial() {
    let (key, _salt) = derive_keys_from_password("correct horse battery staple")
        .expect("derivation should succeed");

    assert!(
        key.iter().any(|&byte| byte != 0),
        "la clé dérivée ne doit pas être entièrement composée de zéros"
    );
}

/// Deux mots de passe très proches (un seul caractère de différence) doivent
/// produire des clés totalement différentes (effet avalanche attendu d'une KDF).
#[test]
fn test_avalanche_effect_on_similar_passwords() {
    let salt = b"a-fixed-test-salt-16b";

    let hash_a = derive_keys_from_password_with_salt("password123", salt).unwrap();
    let hash_b = derive_keys_from_password_with_salt("password124", salt).unwrap();

    assert_ne!(hash_a, hash_b);

    // Vérifie qu'au moins une bonne partie des octets diffère (pas juste 1-2 bits).
    let differing_bytes = hash_a.iter().zip(hash_b.iter()).filter(|(a, b)| a != b).count();
    assert!(
        differing_bytes > hash_a.len() / 4,
        "un changement minime du mot de passe doit produire une différence substantielle (effet avalanche), \
         seulement {} octets sur {} diffèrent",
        differing_bytes,
        hash_a.len()
    );
}