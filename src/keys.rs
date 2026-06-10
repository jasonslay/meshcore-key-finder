use ed25519_dalek::{SigningKey, VerifyingKey};

pub fn public_key_hex(verifying_key: &VerifyingKey) -> String {
    hex::encode_upper(verifying_key.to_bytes())
}

pub fn meshcore_private_key_hex(signing_key: &SigningKey) -> String {
    let seed = signing_key.to_bytes();
    let public = signing_key.verifying_key().to_bytes();
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(&public);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn public_key_is_64_uppercase_hex_chars() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = public_key_hex(&signing_key.verifying_key());
        assert_eq!(public_hex.len(), 64);
        assert!(public_hex
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn private_key_is_seed_plus_public_lowercase() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let private_hex = meshcore_private_key_hex(&signing_key);
        let public_hex = public_key_hex(&signing_key.verifying_key()).to_ascii_lowercase();

        assert_eq!(private_hex.len(), 128);
        assert!(private_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(private_hex.ends_with(&public_hex));
    }
}
