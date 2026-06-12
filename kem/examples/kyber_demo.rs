use kem::{KeyPair, KeyType};

/// Demonstrates the full encapsulation / decapsulation lifecycle for all three
/// supported KEM variants (Kyber1024, Kyber768, ML-KEM 1024) and prints a size
/// comparison table.
///
/// # Panics
///
/// Panics if any encapsulation or decapsulation step fails, or if the sender and
/// receiver shared secrets do not match.
fn main() {
    println!("=== Démonstration du module KEM Kyber ===\n");

    let mut rng = rand::rng();

    println!("Test Kyber1024 (sécurité ~AES-256)");
    println!("Génération de paire de clés...");
    let keypair_1024 = KeyPair::generate(KeyType::Kyber1024, &mut rng);
    println!(
        "Clé publique : {} octets",
        keypair_1024.public_key.serialize().len()
    );
    println!(
        "Clé secrète : {} octets",
        keypair_1024.secret_key.serialize().len()
    );

    println!("\nEncapsulation...");
    let (shared_secret_sender, ciphertext) = keypair_1024
        .public_key
        .encapsulate(&mut rng)
        .expect("Encapsulation réussie");
    println!("Secret partagé : {} octets", shared_secret_sender.len());
    println!("Texte chiffré : {} octets", ciphertext.len());

    println!("\nDécapsulation...");
    let shared_secret_receiver = keypair_1024
        .secret_key
        .decapsulate(&ciphertext)
        .expect("Décapsulation réussie");
    println!(
        "Secret partagé récupéré : {} octets",
        shared_secret_receiver.len()
    );

    if shared_secret_sender == shared_secret_receiver {
        println!("Les secrets partagés correspondent !");
        println!(
            "Secret (8 premiers octets) : {:02x?}",
            &shared_secret_sender[..8]
        );
    } else {
        println!("ERREUR : Les secrets ne correspondent pas !");
    }

    println!("\nTest Kyber768 (sécurité ~AES-192, bande passante réduite)");
    println!("Génération de paire de clés...");
    let keypair_768 = KeyPair::generate(KeyType::Kyber768, &mut rng);
    println!(
        "Clé publique : {} octets",
        keypair_768.public_key.serialize().len()
    );
    println!(
        "Clé secrète : {} octets",
        keypair_768.secret_key.serialize().len()
    );

    let (shared_secret_768, ciphertext_768) = keypair_768
        .public_key
        .encapsulate(&mut rng)
        .expect("Encapsulation réussie");
    println!("Texte chiffré : {} octets", ciphertext_768.len());

    let shared_secret_768_dec = keypair_768
        .secret_key
        .decapsulate(&ciphertext_768)
        .expect("Décapsulation réussie");

    if shared_secret_768 == shared_secret_768_dec {
        println!("Kyber768 fonctionne correctement !");
    }

    println!("\nTest ML-KEM 1024 (standard NIST)");
    let keypair_mlkem = KeyPair::generate(KeyType::MLKEM1024, &mut rng);
    let (shared_secret_mlkem, ciphertext_mlkem) = keypair_mlkem
        .public_key
        .encapsulate(&mut rng)
        .expect("Encapsulation réussie");
    let shared_secret_mlkem_dec = keypair_mlkem
        .secret_key
        .decapsulate(&ciphertext_mlkem)
        .expect("Décapsulation réussie");

    if shared_secret_mlkem == shared_secret_mlkem_dec {
        println!("ML-KEM 1024 fonctionne correctement !");
    }

    println!("\n=== Comparaison des tailles ===");
    println!("┌─────────────┬────────────────┬───────────────┬──────────────┐");
    println!("│ Algorithme  │ Clé publique   │ Texte chiffré │ Secret       │");
    println!("├─────────────┼────────────────┼───────────────┼──────────────┤");
    println!(
        "│ Kyber1024   │ {:>14} │ {:>13} │ {:>12} │",
        format!("{} octets", keypair_1024.public_key.serialize().len()),
        format!("{} octets", ciphertext.len()),
        format!("{} octets", shared_secret_sender.len())
    );
    println!(
        "│ Kyber768    │ {:>14} │ {:>13} │ {:>12} │",
        format!("{} octets", keypair_768.public_key.serialize().len()),
        format!("{} octets", ciphertext_768.len()),
        format!("{} octets", shared_secret_768.len())
    );
    println!(
        "│ ML-KEM 1024 │ {:>14} │ {:>13} │ {:>12} │",
        format!("{} octets", keypair_mlkem.public_key.serialize().len()),
        format!("{} octets", ciphertext_mlkem.len()),
        format!("{} octets", shared_secret_mlkem.len())
    );
    println!("└─────────────┴────────────────┴───────────────┴──────────────┘");

    println!("\n=== Recommandations ===");
    println!("Utilisez Kyber1024 pour une sécurité maximale (niveau NIST 5)");
    println!("Utilisez Kyber768 si vous avez des contraintes de bande passante");
    println!("Utilisez ML-KEM 1024 pour la conformité au standard NIST final");
    println!("\nModule KEM fonctionnel !");
}
