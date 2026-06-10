pub fn validate_prefix(prefix: &str) -> Result<String, String> {
    let normalized = prefix.to_ascii_uppercase();
    if normalized.is_empty() {
        return Err("prefix must be non-empty hexadecimal characters".into());
    }
    if normalized.len() > 64 {
        return Err("prefix cannot be longer than a 64-character public key".into());
    }
    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("prefix must be non-empty hexadecimal characters".into());
    }
    Ok(normalized)
}

pub fn matches_prefix_hex(public_key: &[u8; 32], prefix: &str, avoid_reserved: bool) -> bool {
    if avoid_reserved && (public_key[0] == 0x00 || public_key[0] == 0xFF) {
        return false;
    }

    let prefix = prefix.as_bytes();
    let mut byte_idx = 0usize;
    let mut high_nibble = true;

    for &ch in prefix {
        let expected = match ch {
            b'0'..=b'9' => ch - b'0',
            b'A'..=b'F' => ch - b'A' + 10,
            _ => return false,
        };

        if byte_idx >= 32 {
            return false;
        }

        let actual = if high_nibble {
            public_key[byte_idx] >> 4
        } else {
            let value = public_key[byte_idx] & 0x0f;
            byte_idx += 1;
            value
        };

        if actual != expected {
            return false;
        }

        high_nibble = !high_nibble;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_prefix_normalizes_case() {
        assert_eq!(validate_prefix("beef").unwrap(), "BEEF");
        assert_eq!(validate_prefix("Ab12").unwrap(), "AB12");
    }

    #[test]
    fn validate_prefix_rejects_invalid() {
        assert!(validate_prefix("").is_err());
        assert!(validate_prefix("GHIJ").is_err());
        assert!(validate_prefix(&"A".repeat(65)).is_err());
    }

    #[test]
    fn matches_even_byte_prefix() {
        let mut public_key = [0u8; 32];
        public_key[0] = 0xBE;
        public_key[1] = 0xEF;
        assert!(matches_prefix_hex(&public_key, "BEEF", true));
        assert!(!matches_prefix_hex(&public_key, "BEED", true));
    }

    #[test]
    fn matches_odd_nibble_prefix() {
        let mut public_key = [0u8; 32];
        public_key[0] = 0xA1;
        assert!(matches_prefix_hex(&public_key, "A", true));
        assert!(!matches_prefix_hex(&public_key, "B", true));
    }

    #[test]
    fn skips_reserved_prefixes() {
        let mut reserved = [0u8; 32];
        reserved[0] = 0x00;
        reserved[1] = 0xAB;
        assert!(!matches_prefix_hex(&reserved, "00", true));
        assert!(matches_prefix_hex(&reserved, "00", false));

        let mut reserved_ff = [0u8; 32];
        reserved_ff[0] = 0xFF;
        reserved_ff[1] = 0xAB;
        assert!(!matches_prefix_hex(&reserved_ff, "FF", true));
    }
}
