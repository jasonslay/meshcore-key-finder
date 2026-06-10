#[derive(Clone, Debug)]
pub struct PrefixMatcher {
    nibbles: [u8; 64],
    len: u8,
    avoid_reserved: bool,
}

impl PrefixMatcher {
    pub fn new(prefix: &str, avoid_reserved: bool) -> Result<Self, String> {
        let normalized = validate_prefix(prefix)?;
        let mut nibbles = [0u8; 64];
        for (index, ch) in normalized.bytes().enumerate() {
            nibbles[index] = match ch {
                b'0'..=b'9' => ch - b'0',
                b'A'..=b'F' => ch - b'A' + 10,
                _ => unreachable!("validate_prefix guarantees hex digits"),
            };
        }

        Ok(Self {
            nibbles,
            len: normalized.len() as u8,
            avoid_reserved,
        })
    }

    pub fn prefix_len(&self) -> usize {
        self.len as usize
    }

    pub fn avoid_reserved(&self) -> bool {
        self.avoid_reserved
    }

    pub fn matches(&self, public_key: &[u8; 32]) -> bool {
        if self.avoid_reserved && (public_key[0] == 0x00 || public_key[0] == 0xFF) {
            return false;
        }

        let mut byte_idx = 0usize;
        let mut high_nibble = true;

        for index in 0..self.len as usize {
            let expected = self.nibbles[index];
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
}

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
    PrefixMatcher::new(prefix, avoid_reserved)
        .expect("prefix should already be validated")
        .matches(public_key)
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
    fn prefix_matcher_matches_even_byte_prefix() {
        let mut public_key = [0u8; 32];
        public_key[0] = 0xBE;
        public_key[1] = 0xEF;
        let matcher = PrefixMatcher::new("BEEF", true).unwrap();
        assert!(matcher.matches(&public_key));
        let mismatch = PrefixMatcher::new("BEED", true).unwrap();
        assert!(!mismatch.matches(&public_key));
    }

    #[test]
    fn prefix_matcher_matches_odd_nibble_prefix() {
        let mut public_key = [0u8; 32];
        public_key[0] = 0xA1;
        let matcher = PrefixMatcher::new("A", true).unwrap();
        assert!(matcher.matches(&public_key));
        let mismatch = PrefixMatcher::new("B", true).unwrap();
        assert!(!mismatch.matches(&public_key));
    }

    #[test]
    fn prefix_matcher_skips_reserved_prefixes() {
        let mut reserved = [0u8; 32];
        reserved[0] = 0x00;
        reserved[1] = 0xAB;
        let strict = PrefixMatcher::new("00", true).unwrap();
        assert!(!strict.matches(&reserved));
        let permissive = PrefixMatcher::new("00", false).unwrap();
        assert!(permissive.matches(&reserved));

        let mut reserved_ff = [0u8; 32];
        reserved_ff[0] = 0xFF;
        reserved_ff[1] = 0xAB;
        let strict_ff = PrefixMatcher::new("FF", true).unwrap();
        assert!(!strict_ff.matches(&reserved_ff));
    }

    #[test]
    fn prefix_matcher_matches_legacy_helper() {
        let mut public_key = [0u8; 32];
        public_key[0] = 0xBE;
        public_key[1] = 0xEF;
        assert_eq!(
            PrefixMatcher::new("BEEF", true)
                .unwrap()
                .matches(&public_key),
            matches_prefix_hex(&public_key, "BEEF", true),
        );
    }
}
