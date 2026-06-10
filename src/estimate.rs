//! Search difficulty estimates from prefix length.

pub struct SearchEstimate {
    pub prefix_len: usize,
    pub average_attempts: u128,
}

pub fn format_with_commas(n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }

    let mut parts = Vec::new();
    let mut remaining = n;
    while remaining > 0 {
        parts.push(remaining % 1000);
        remaining /= 1000;
    }

    let mut formatted = parts.pop().unwrap().to_string();
    for part in parts.into_iter().rev() {
        formatted.push_str(&format!(",{part:03}"));
    }
    formatted
}

pub fn average_attempts(prefix_len: usize, avoid_reserved: bool) -> u128 {
    let base = 16u128.pow(prefix_len as u32);
    if avoid_reserved {
        // Keys with 0x00 or 0xFF as the first byte are skipped (~2/256 of candidates).
        base.saturating_mul(256) / 254
    } else {
        base
    }
}

pub fn search_estimate(prefix_len: usize, avoid_reserved: bool) -> SearchEstimate {
    SearchEstimate {
        prefix_len,
        average_attempts: average_attempts(prefix_len, avoid_reserved),
    }
}

pub fn format_attempts(n: u128) -> String {
    if n <= u64::MAX as u128 {
        format_with_commas(n as u64)
    } else {
        format_with_commas_u128(n)
    }
}

fn format_with_commas_u128(mut n: u128) -> String {
    if n == 0 {
        return "0".to_string();
    }

    let mut parts = Vec::new();
    while n > 0 {
        parts.push((n % 1000) as u32);
        n /= 1000;
    }

    let mut formatted = parts.pop().unwrap().to_string();
    for part in parts.into_iter().rev() {
        formatted.push_str(&format!(",{part:03}"));
    }
    formatted
}

pub fn format_duration(seconds: f64) -> String {
    if seconds < 1.0 {
        return format!("{:.2}s", seconds.max(0.01));
    }
    if seconds < 60.0 {
        return format!("{:.1}s", seconds);
    }
    if seconds < 3600.0 {
        return format!("{:.1} min", seconds / 60.0);
    }
    if seconds < 86_400.0 {
        return format!("{:.1} hours", seconds / 3600.0);
    }
    format!("{:.1} days", seconds / 86_400.0)
}

pub fn format_duration_signed(seconds: f64) -> String {
    if seconds == 0.0 {
        return "0.00s".to_string();
    }
    if seconds < 0.0 {
        return format!("-{}", format_duration(-seconds));
    }
    format_duration(seconds)
}

pub fn format_search_estimate(estimate: &SearchEstimate) -> String {
    let attempts = format_attempts(estimate.average_attempts);
    let chars = estimate.prefix_len;
    let char_label = if chars == 1 { "char" } else { "chars" };

    format!("{attempts} average attempts ({chars} hex {char_label})")
}

pub fn format_eta(estimate: &SearchEstimate, attempts: u64, elapsed_secs: f64) -> Option<String> {
    if elapsed_secs <= 0.0 || attempts == 0 {
        return None;
    }

    let rate = attempts as f64 / elapsed_secs;
    if rate <= 0.0 {
        return None;
    }

    let remaining = estimate.average_attempts as f64 - attempts as f64;
    let seconds = remaining / rate;
    Some(format_duration_signed(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_with_commas_formats_large_numbers() {
        assert_eq!(format_with_commas(0), "0");
        assert_eq!(format_with_commas(999), "999");
        assert_eq!(format_with_commas(1_000), "1,000");
        assert_eq!(format_with_commas(1_234_567), "1,234,567");
    }

    #[test]
    fn average_attempts_scales_by_sixteen_per_char() {
        assert_eq!(average_attempts(1, false), 16);
        assert_eq!(average_attempts(2, false), 256);
        assert_eq!(average_attempts(4, false), 65_536);
        assert_eq!(average_attempts(6, false), 16_777_216);
    }

    #[test]
    fn avoid_reserved_increases_average_attempts_slightly() {
        assert!(average_attempts(4, true) > average_attempts(4, false));
    }

    #[test]
    fn format_duration_covers_scales() {
        assert_eq!(format_duration(0.16), "0.16s");
        assert_eq!(format_duration(12.4), "12.4s");
        assert_eq!(format_duration(90.0), "1.5 min");
        assert_eq!(format_duration(7200.0), "2.0 hours");
        assert_eq!(format_duration(200_000.0), "2.3 days");
    }

    #[test]
    fn format_search_estimate_for_beef() {
        let estimate = search_estimate(4, false);
        let message = format_search_estimate(&estimate);
        assert!(message.contains("65,536"));
        assert!(message.contains("4 hex chars"));
        assert!(!message.contains("400,000"));
    }

    #[test]
    fn format_eta_uses_current_rate() {
        let estimate = search_estimate(4, false);
        assert_eq!(format_eta(&estimate, 32_768, 1.0), Some("1.0s".to_string()));
    }

    #[test]
    fn format_eta_shows_negative_when_past_average() {
        let estimate = search_estimate(2, false);
        assert_eq!(format_eta(&estimate, 300, 1.0), Some("-0.15s".to_string()));
    }
}
