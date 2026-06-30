//! Parsing of the L402 `WWW-Authenticate` header value.

/// Extract the raw macaroon (base64) and invoice (bolt11) strings from a
/// `WWW-Authenticate` header value of the form:
///   `L402 macaroon="<b64>", invoice="<bolt11>"`
pub fn parse_l402_header_value(header: &str) -> Option<(String, String)> {
    let mac = header.split("macaroon=\"").nth(1)?.split('"').next()?.to_string();
    let inv = header.split("invoice=\"").nth(1)?.split('"').next()?.to_string();
    Some((mac, inv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_header() {
        let (mac, inv) =
            parse_l402_header_value(r#"L402 macaroon="AbCd123==", invoice="lnbc100n1pabc""#)
                .expect("well-formed header");
        assert_eq!(mac, "AbCd123==");
        assert_eq!(inv, "lnbc100n1pabc");
    }

    #[test]
    fn missing_macaroon_returns_none() {
        assert!(parse_l402_header_value(r#"L402 invoice="lnbc100n1pabc""#).is_none());
    }

    #[test]
    fn missing_invoice_returns_none() {
        assert!(parse_l402_header_value(r#"L402 macaroon="abc""#).is_none());
    }

    #[test]
    fn empty_header_returns_none() {
        assert!(parse_l402_header_value("").is_none());
    }

    /// The first quoted value after each key is taken; extra fields don't break it.
    #[test]
    fn ignores_trailing_fields() {
        let (mac, inv) =
            parse_l402_header_value(r#"L402 macaroon="m1", invoice="i1", extra="x""#).unwrap();
        assert_eq!(mac, "m1");
        assert_eq!(inv, "i1");
    }
}
