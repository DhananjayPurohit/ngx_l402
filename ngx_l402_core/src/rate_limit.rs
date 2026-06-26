//! Parsing of the `l402_invoice_rate_limit` directive value.

/// Parse a rate-limit directive value into `(max_requests, window_seconds)`.
/// Accepts `"<N>r/s"`, `"<N>r/m"`, `"<N>r/h"`, or a bare `"<N>"` (defaulting to a
/// 60-second window). Returns `None` on a malformed value — callers treat that
/// as "no limit configured", so a parse bug must be caught here rather than
/// silently disabling rate limiting.
pub fn parse_rate_limit(val: &str) -> Option<(u32, u64)> {
    let val = val.trim();
    if let Some(n) = val.strip_suffix("r/m") {
        n.trim().parse::<u32>().ok().map(|c| (c, 60))
    } else if let Some(n) = val.strip_suffix("r/h") {
        n.trim().parse::<u32>().ok().map(|c| (c, 3600))
    } else if let Some(n) = val.strip_suffix("r/s") {
        n.trim().parse::<u32>().ok().map(|c| (c, 1))
    } else {
        val.parse::<u32>().ok().map(|c| (c, 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_per_second_minute_hour() {
        assert_eq!(parse_rate_limit("5r/s"), Some((5, 1)));
        assert_eq!(parse_rate_limit("100r/m"), Some((100, 60)));
        assert_eq!(parse_rate_limit("1000r/h"), Some((1000, 3600)));
    }

    #[test]
    fn bare_number_defaults_to_per_minute() {
        assert_eq!(parse_rate_limit("30"), Some((30, 60)));
    }

    #[test]
    fn tolerates_surrounding_and_inner_whitespace() {
        assert_eq!(parse_rate_limit("  10 r/s "), Some((10, 1)));
    }

    /// A malformed value must return None (not a wrong limit) — callers read
    /// None as "unlimited", so this is the line between safe and silently broken.
    #[test]
    fn rejects_malformed() {
        assert_eq!(parse_rate_limit(""), None);
        assert_eq!(parse_rate_limit("abc"), None);
        assert_eq!(parse_rate_limit("r/s"), None);
        assert_eq!(parse_rate_limit("-5r/m"), None); // u32 rejects negative
    }
}
