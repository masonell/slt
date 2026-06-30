//! Ed25519 keypair generation command.

use ed25519_dalek::SigningKey;

/// Generate an Ed25519 keypair and print to stdout.
pub fn generate_keys() {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);

    let signing_key = SigningKey::from_bytes(&bytes);
    let verifying_key = signing_key.verifying_key();

    println!("privkey: {}", hex::encode(signing_key.to_bytes()));
    println!("pubkey:  {}", hex::encode(verifying_key.to_bytes()));
}

#[cfg(test)]
mod tests {
    #[test]
    fn generate_keys_runs_without_error() {
        super::generate_keys();
    }
}
