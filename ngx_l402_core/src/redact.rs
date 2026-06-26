//! Redaction of secrets from connection strings for safe logging.

/// Redact the userinfo (`user:pass`) from a `scheme://user:pass@host` URL so it
/// can be logged without leaking the credential. Non-URL or credential-less
/// inputs are returned unchanged.
pub fn redact_redis_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.split_once('@') {
        Some((_userinfo, host)) => format!("{}://***@{}", scheme, host),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_userinfo() {
        assert_eq!(
            redact_redis_url("redis://user:s3cret@host:6379/0"),
            "redis://***@host:6379/0"
        );
    }

    #[test]
    fn redacts_password_only_userinfo() {
        assert_eq!(redact_redis_url("rediss://:pw@host"), "rediss://***@host");
    }

    #[test]
    fn leaves_credential_less_url_unchanged() {
        assert_eq!(redact_redis_url("redis://host:6379"), "redis://host:6379");
    }

    #[test]
    fn leaves_non_url_unchanged() {
        assert_eq!(redact_redis_url("not-a-url"), "not-a-url");
    }

    /// The redacted output must never contain the secret or the username.
    #[test]
    fn output_never_contains_the_secret() {
        let out = redact_redis_url("redis://admin:topsecret@host");
        assert!(!out.contains("topsecret"));
        assert!(!out.contains("admin"));
    }
}
