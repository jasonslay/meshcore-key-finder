use curve25519_dalek::EdwardsPoint;
use ed25519_dalek::VerifyingKey;
use rand_core::RngCore;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// MeshCore firmware test vector from `LocalIdentity::validatePrivateKey`.
const MESHCORE_TEST_CLIENT_PRIVATE: [u8; 64] = [
    0x70, 0x65, 0xe1, 0x8f, 0xd9, 0xfa, 0xbb, 0x70, 0xc1, 0xed, 0x90, 0xdc, 0xa1, 0x99, 0x07, 0xde,
    0x69, 0x8c, 0x88, 0xb7, 0x09, 0xea, 0x14, 0x6e, 0xaf, 0xd9, 0x3d, 0x9b, 0x83, 0x0c, 0x7b, 0x60,
    0xc4, 0x68, 0x11, 0x93, 0xc7, 0x9b, 0xbc, 0x39, 0x94, 0x5b, 0xa8, 0x06, 0x41, 0x04, 0xbb, 0x61,
    0x8f, 0x8f, 0xd7, 0xa8, 0x4a, 0x0a, 0xf6, 0xf5, 0x70, 0x33, 0xd6, 0xe8, 0xdd, 0xcd, 0x64, 0x71,
];

const MESHCORE_TEST_CLIENT_PUBLIC: [u8; 32] = [
    0x1e, 0xc7, 0x71, 0x75, 0xb0, 0x91, 0x8e, 0xd2, 0x06, 0xf9, 0xae, 0x04, 0xec, 0x13, 0x6d, 0x6d,
    0x5d, 0x43, 0x15, 0xbb, 0x26, 0x30, 0x54, 0x27, 0xf6, 0x45, 0xb4, 0x92, 0xe9, 0x35, 0x0c, 0x10,
];

/// Real device sample from meshcore-decoder tests (used in unit tests).
#[cfg(test)]
const REAL_DEVICE_PRIVATE_HEX: &str = "18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5";
#[cfg(test)]
const REAL_DEVICE_PUBLIC_HEX: &str =
    "4852b69364572b52efa1b6bb3e6d0abed4f389a1cbfbb60a9bba2cce649caf0e";

pub fn public_key_hex_from_bytes(public_key: &[u8; 32]) -> String {
    hex::encode_upper(public_key)
}

pub fn meshcore_private_key_hex_from_bytes(orlp: &[u8; 64]) -> String {
    hex::encode(orlp)
}

/// MeshCore stores the orlp/ed25519 expanded private key: clamped scalar `a` || `RH`,
/// where `LH || RH = SHA-512(seed)`.
pub fn seed_to_orlp_private_key(seed: &[u8; 32]) -> [u8; 64] {
    let digest = Sha512::default().chain_update(seed).finalize();
    let mut orlp = [0u8; 64];
    orlp.copy_from_slice(digest.as_ref());
    orlp[0] &= 248;
    orlp[31] &= 63;
    orlp[31] |= 64;
    orlp
}

fn clamp_orlp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 63;
    scalar[31] |= 64;
}

/// Derive the public key the same way MeshCore firmware does (`ge_scalarmult_base`).
pub fn public_key_bytes_from_orlp(orlp: &[u8; 64]) -> [u8; 32] {
    let scalar: [u8; 32] = orlp[..32]
        .try_into()
        .expect("orlp private key must include a 32-byte scalar");
    EdwardsPoint::mul_base_clamped(scalar)
        .compress()
        .to_bytes()
}

pub fn generate_meshcore_keypair(rng: &mut impl RngCore) -> ([u8; 32], [u8; 64]) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let orlp = seed_to_orlp_private_key(&seed);
    let public_key = public_key_bytes_from_orlp(&orlp);
    (public_key, orlp)
}

/// Validates that an exported key matches MeshCore firmware import rules.
pub fn validate_found_key(orlp: &[u8; 64], public_key: &[u8; 32]) -> Result<(), String> {
    if public_key_bytes_from_orlp(orlp) != *public_key {
        return Err("public key does not match MeshCore derivation from private key".into());
    }
    validate_orlp_private_key(orlp, Some(public_key))
}

pub fn validate_orlp_private_key(
    orlp: &[u8; 64],
    expected_public: Option<&[u8; 32]>,
) -> Result<(), String> {
    let derived_public = public_key_bytes_from_orlp(orlp);

    if let Some(expected) = expected_public {
        if derived_public != *expected {
            return Err("orlp private key does not derive the expected public key".into());
        }
    }

    if derived_public[0] == 0x00 || derived_public[0] == 0xFF {
        return Err("public key uses reserved MeshCore prefix 0x00 or 0xFF".into());
    }

    validate_meshcore_ecdh(orlp, &derived_public)
}

fn validate_meshcore_ecdh(orlp: &[u8; 64], derived_public: &[u8; 32]) -> Result<(), String> {
    let ss1 = ed25519_key_exchange(orlp, &MESHCORE_TEST_CLIENT_PUBLIC)?;
    let ss2 = ed25519_key_exchange(&MESHCORE_TEST_CLIENT_PRIVATE, derived_public)?;

    if ss1 != ss2 {
        return Err("MeshCore ECDH validation failed".into());
    }

    if ss1.iter().all(|byte| *byte == 0) {
        return Err("MeshCore ECDH validation produced an all-zero shared secret".into());
    }

    Ok(())
}

fn ed25519_key_exchange(
    orlp_private: &[u8; 64],
    ed25519_public: &[u8; 32],
) -> Result<[u8; 32], String> {
    let static_secret = x25519_static_secret_from_orlp(orlp_private);
    let verifying_key = VerifyingKey::from_bytes(ed25519_public)
        .map_err(|error| format!("invalid Ed25519 public key for ECDH: {error}"))?;
    let montgomery = verifying_key.to_montgomery();
    let x_public = X25519PublicKey::from(*montgomery.as_bytes());
    Ok(static_secret.diffie_hellman(&x_public).to_bytes())
}

fn x25519_static_secret_from_orlp(orlp_private: &[u8; 64]) -> X25519StaticSecret {
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&orlp_private[..32]);
    clamp_orlp_scalar(&mut scalar);
    X25519StaticSecret::from(scalar)
}

pub fn parse_meshcore_private_key_hex(private_hex: &str) -> Result<[u8; 64], String> {
    let bytes =
        hex::decode(private_hex).map_err(|error| format!("invalid private key hex: {error}"))?;
    if bytes.len() != 64 {
        return Err(format!(
            "MeshCore private key must be 64 bytes, got {}",
            bytes.len()
        ));
    }

    let orlp: [u8; 64] = bytes.try_into().expect("validated length is 64 bytes");
    validate_orlp_private_key(&orlp, None)?;
    Ok(orlp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn hex_to_32(hex_str: &str) -> [u8; 32] {
        hex::decode(hex_str)
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn hex_to_64(hex_str: &str) -> [u8; 64] {
        hex::decode(hex_str)
            .expect("valid hex")
            .try_into()
            .expect("64 bytes")
    }

    #[test]
    fn public_key_is_64_uppercase_hex_chars() {
        let (public_key, _) = generate_meshcore_keypair(&mut OsRng);
        let public_hex = public_key_hex_from_bytes(&public_key);
        assert_eq!(public_hex.len(), 64);
        assert!(public_hex
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn private_key_is_orlp_format_lowercase_hex() {
        let (_, orlp) = generate_meshcore_keypair(&mut OsRng);
        let private_hex = meshcore_private_key_hex_from_bytes(&orlp);

        assert_eq!(private_hex.len(), 128);
        assert!(private_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn meshcore_test_vector_derives_expected_public_key() {
        let derived = public_key_bytes_from_orlp(&MESHCORE_TEST_CLIENT_PRIVATE);
        assert_eq!(derived, MESHCORE_TEST_CLIENT_PUBLIC);
        validate_orlp_private_key(&MESHCORE_TEST_CLIENT_PRIVATE, Some(&derived))
            .expect("MeshCore test vector should validate");
    }

    #[test]
    fn real_device_sample_derives_expected_public_key() {
        let orlp = hex_to_64(REAL_DEVICE_PRIVATE_HEX);
        let expected = hex_to_32(REAL_DEVICE_PUBLIC_HEX);
        let derived = public_key_bytes_from_orlp(&orlp);
        assert_eq!(derived, expected);
        validate_orlp_private_key(&orlp, Some(&expected)).expect("real device sample validates");
    }

    #[test]
    fn generated_keys_validate_for_meshcore_import() {
        let (public_key, orlp) = generate_meshcore_keypair(&mut OsRng);
        assert_scalar_is_clamped(&orlp[..32]);
        validate_found_key(&orlp, &public_key).expect("generated key should import into MeshCore");

        let private_hex = meshcore_private_key_hex_from_bytes(&orlp);
        let parsed = parse_meshcore_private_key_hex(&private_hex).expect("parse MeshCore export");
        assert_eq!(parsed, orlp);
    }

    #[test]
    fn seed_to_orlp_clamps_scalar() {
        let orlp = seed_to_orlp_private_key(&[0xFF; 32]);
        assert_scalar_is_clamped(&orlp[..32]);
    }

    #[test]
    fn generated_private_key_scalar_is_clamped() {
        let (_, orlp) = generate_meshcore_keypair(&mut OsRng);
        assert_scalar_is_clamped(&orlp[..32]);
    }

    fn assert_scalar_is_clamped(scalar: &[u8]) {
        let mut reclamped = [0u8; 32];
        reclamped.copy_from_slice(scalar);
        clamp_orlp_scalar(&mut reclamped);
        assert_eq!(
            reclamped, scalar,
            "scalar bytes must already be Ed25519-clamped"
        );
    }
}
