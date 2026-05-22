//! MPP-Lightning wire format (charge intent).
//!
//! Implements the HTTP envelope for the Payment HTTP Authentication Scheme
//! (`draft-ryan-httpauth-payment`) using the `lightning` method, in parity
//! with `mppx` and `@buildonspark/lightning-mpp-sdk`. Pure functions, no
//! nginx types — the wiring into the access-phase handler lives in `lib.rs`.
//!
//! ## Security model
//!
//! Unlike L402 (where a macaroon HMAC anchors `payment_hash` to the server),
//! MPP binds the entire challenge via `id = HMAC-SHA256(secret, realm | method
//! | intent | request | expires | digest | opaque)`. The client echoes the
//! full challenge in the credential; the server recomputes the HMAC and
//! constant-time compares it to the echoed `id`. If they match, every echoed
//! field — including `methodDetails.paymentHash` — is server-trusted, so no
//! Lightning-node lookup is required to confirm server issuance.
//!
//! Verification then checks `sha256(preimage) == paymentHash` and that the
//! challenge hasn't expired. Replay protection is the caller's responsibility
//! (the existing scheme-agnostic preimage cache in `lib.rs` is the right home).
//!
//! ## Wire format references
//!
//! - Challenge serialization: `wevm/mppx` `src/Challenge.ts`
//! - Credential serialization: `wevm/mppx` `src/Credential.ts`
//! - Receipt serialization: `wevm/mppx` `src/Receipt.ts`
//! - Lightning method schema: `buildonspark/lightning-mpp-sdk` `sdk/src/Methods.ts`

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// All inputs needed to issue an MPP-Lightning challenge for a single
/// charge-intent request.
#[derive(Debug)]
pub struct Challenge<'a> {
    /// Server realm — typically the request `Host` header.
    pub realm: &'a str,
    /// BOLT11-encoded payment request the client must settle.
    pub invoice: &'a str,
    /// SHA-256 of the invoice's preimage, lowercase hex. Convenience field;
    /// MUST agree with what's encoded in `invoice`.
    pub payment_hash_hex: &'a str,
    /// Invoice amount in satoshis. Emitted as a decimal string per the
    /// lightning-mpp-sdk schema (`amount: z.string()`).
    pub amount_sat: u64,
    /// Lightning network identifier (`"mainnet"`, `"regtest"`, `"signet"`).
    /// Optional but recommended; clients use it to reject mismatched invoices.
    pub network: Option<&'a str>,
    /// Human-readable label for the payment.
    pub description: Option<&'a str>,
    /// RFC 3339 / ISO 8601 datetime at which this challenge must no longer
    /// be honored. Should never be set later than the BOLT11 invoice expiry.
    pub expires: Option<&'a str>,
    /// Opaque server correlation handle, base64url-encoded. Clients MUST
    /// echo unchanged in the credential.
    pub opaque: Option<&'a str>,
}

/// Build the JCS-canonical PaymentRequest JSON for a lightning charge.
///
/// Mirrors the `Methods.charge` zod schema from lightning-mpp-sdk:
/// ```text
/// { amount, currency?, description?, methodDetails: { invoice, paymentHash?, network? } }
/// ```
///
/// `serde_json::Map` is backed by `BTreeMap` when the `preserve_order` feature
/// is off (the default), so keys serialize in lexicographic byte order — which
/// is the JCS sort order for the ASCII keys used here.
pub fn serialize_payment_request_json(c: &Challenge<'_>) -> String {
    let mut details = serde_json::Map::new();
    details.insert(
        "invoice".to_string(),
        serde_json::Value::String(c.invoice.to_string()),
    );
    details.insert(
        "paymentHash".to_string(),
        serde_json::Value::String(c.payment_hash_hex.to_string()),
    );
    if let Some(n) = c.network {
        details.insert(
            "network".to_string(),
            serde_json::Value::String(n.to_string()),
        );
    }

    let mut req = serde_json::Map::new();
    req.insert(
        "amount".to_string(),
        serde_json::Value::String(c.amount_sat.to_string()),
    );
    req.insert(
        "currency".to_string(),
        serde_json::Value::String("sat".to_string()),
    );
    if let Some(d) = c.description {
        req.insert(
            "description".to_string(),
            serde_json::Value::String(d.to_string()),
        );
    }
    req.insert(
        "methodDetails".to_string(),
        serde_json::Value::Object(details),
    );

    serde_json::to_string(&serde_json::Value::Object(req))
        .expect("serializing static-shape JSON cannot fail")
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute the HMAC-SHA256 challenge ID over the canonical
/// `realm | method | intent | request | expires | digest | opaque` input.
///
/// Optional fields use empty strings when absent so the slot count is stable
/// — mirrors `wevm/mppx`'s `idBindingInput`.
pub fn compute_challenge_id(
    secret_key: &[u8],
    realm: &str,
    intent: &str,
    request_serialized: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
) -> String {
    let input = [
        realm,
        "lightning",
        intent,
        request_serialized,
        expires.unwrap_or(""),
        digest.unwrap_or(""),
        opaque.unwrap_or(""),
    ]
    .join("|");

    let mut mac =
        HmacSha256::new_from_slice(secret_key).expect("HMAC accepts any key length");
    mac.update(input.as_bytes());
    b64url(&mac.finalize().into_bytes())
}

/// Format a complete `WWW-Authenticate: Payment …` header value.
///
/// The output omits the header name — callers pass the returned string as
/// the value to `add_header_out("WWW-Authenticate", …)`.
pub fn format_challenge(secret_key: &[u8], c: &Challenge<'_>) -> String {
    let request_serialized = b64url(serialize_payment_request_json(c).as_bytes());
    let id = compute_challenge_id(
        secret_key,
        c.realm,
        "charge",
        &request_serialized,
        c.expires,
        None,
        c.opaque,
    );

    let mut parts: Vec<String> = Vec::with_capacity(8);
    parts.push(format!(r#"id="{}""#, id));
    parts.push(format!(r#"realm="{}""#, c.realm));
    parts.push(r#"method="lightning""#.to_string());
    parts.push(r#"intent="charge""#.to_string());
    parts.push(format!(r#"request="{}""#, request_serialized));
    if let Some(d) = c.description {
        parts.push(format!(r#"description="{}""#, d));
    }
    if let Some(e) = c.expires {
        parts.push(format!(r#"expires="{}""#, e));
    }
    if let Some(o) = c.opaque {
        parts.push(format!(r#"opaque="{}""#, o));
    }
    format!("Payment {}", parts.join(", "))
}

/// Fields recovered from a parsed `Authorization: Payment …` header. Mirrors
/// the JSON shape `wevm/mppx` `Credential.serialize` emits.
#[derive(Debug, Clone)]
pub struct ParsedCredential {
    pub challenge_id: String,
    pub realm: String,
    pub method: String,
    pub intent: String,
    /// The opaque base64url payload of the `request` field as it appeared on
    /// the wire. Used unchanged when recomputing the challenge HMAC.
    pub request_serialized: String,
    pub expires: Option<String>,
    pub digest: Option<String>,
    pub opaque: Option<String>,
    pub preimage_hex: String,
    /// Lowercase hex `payment_hash` extracted from `request.methodDetails`.
    pub payment_hash_hex: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CredentialError {
    MissingScheme,
    InvalidBase64,
    InvalidJson,
    MissingField(&'static str),
    InvalidMethod,
    InvalidIntent,
    HmacMismatch,
    HashMismatch,
    Expired,
    InvalidPreimage,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialError::MissingScheme => write!(f, "missing Payment scheme prefix"),
            CredentialError::InvalidBase64 => write!(f, "invalid base64url encoding"),
            CredentialError::InvalidJson => write!(f, "invalid JSON"),
            CredentialError::MissingField(name) => write!(f, "missing field: {}", name),
            CredentialError::InvalidMethod => write!(f, "method must be \"lightning\""),
            CredentialError::InvalidIntent => write!(f, "intent must be \"charge\""),
            CredentialError::HmacMismatch => write!(f, "challenge id HMAC mismatch"),
            CredentialError::HashMismatch => write!(f, "preimage does not hash to payment_hash"),
            CredentialError::Expired => write!(f, "challenge has expired"),
            CredentialError::InvalidPreimage => write!(f, "preimage is not valid hex"),
        }
    }
}

/// Parse an `Authorization: Payment …` header value into its structural parts.
///
/// Does not verify the HMAC or the preimage hash — those run in
/// [`verify_credential`].
pub fn parse_credential(header_value: &str) -> Result<ParsedCredential, CredentialError> {
    let token = header_value
        .trim()
        .strip_prefix("Payment ")
        .ok_or(CredentialError::MissingScheme)?
        .trim();

    let json_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| CredentialError::InvalidBase64)?;
    let parsed: serde_json::Value =
        serde_json::from_slice(&json_bytes).map_err(|_| CredentialError::InvalidJson)?;

    let challenge = parsed
        .get("challenge")
        .ok_or(CredentialError::MissingField("challenge"))?;
    let payload = parsed
        .get("payload")
        .ok_or(CredentialError::MissingField("payload"))?;

    let str_field = |obj: &serde_json::Value, name: &'static str| -> Result<String, CredentialError> {
        obj.get(name)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(CredentialError::MissingField(name))
    };

    let challenge_id = str_field(challenge, "id")?;
    let realm = str_field(challenge, "realm")?;
    let method = str_field(challenge, "method")?;
    let intent = str_field(challenge, "intent")?;
    let request_serialized = str_field(challenge, "request")?;
    let expires = challenge
        .get("expires")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let digest = challenge
        .get("digest")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let opaque = challenge
        .get("opaque")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if method != "lightning" {
        return Err(CredentialError::InvalidMethod);
    }
    if intent != "charge" {
        return Err(CredentialError::InvalidIntent);
    }

    let preimage_hex = str_field(payload, "preimage")?;

    // Decode the echoed PaymentRequest to read its `methodDetails.paymentHash`.
    // Reading from this echoed copy is safe ONLY after the HMAC check in
    // verify_credential confirms the field hasn't been tampered with.
    let request_json_bytes = URL_SAFE_NO_PAD
        .decode(&request_serialized)
        .map_err(|_| CredentialError::InvalidBase64)?;
    let request_obj: serde_json::Value = serde_json::from_slice(&request_json_bytes)
        .map_err(|_| CredentialError::InvalidJson)?;
    let payment_hash_hex = request_obj
        .get("methodDetails")
        .and_then(|v| v.get("paymentHash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or(CredentialError::MissingField("methodDetails.paymentHash"))?;

    Ok(ParsedCredential {
        challenge_id,
        realm,
        method,
        intent,
        request_serialized,
        expires,
        digest,
        opaque,
        preimage_hex,
        payment_hash_hex,
    })
}

/// Verify the HMAC of an echoed challenge, that any `expires` is still in
/// the future, and that `sha256(preimage) == payment_hash`.
///
/// `now_unix_ms` is injected so callers can pin a single clock reading per
/// request and keep this function pure.
///
/// Returns `Ok(())` only when every check passes. Replay protection is
/// the caller's responsibility — this function is stateless.
pub fn verify_credential(
    cred: &ParsedCredential,
    secret_key: &[u8],
    now_unix_ms: i64,
) -> Result<(), CredentialError> {
    let expected_id = compute_challenge_id(
        secret_key,
        &cred.realm,
        &cred.intent,
        &cred.request_serialized,
        cred.expires.as_deref(),
        cred.digest.as_deref(),
        cred.opaque.as_deref(),
    );
    if !constant_time_eq(expected_id.as_bytes(), cred.challenge_id.as_bytes()) {
        return Err(CredentialError::HmacMismatch);
    }

    if let Some(exp) = &cred.expires {
        let exp_ms = parse_rfc3339_ms(exp).ok_or(CredentialError::Expired)?;
        if now_unix_ms > exp_ms {
            return Err(CredentialError::Expired);
        }
    }

    let preimage = hex::decode(&cred.preimage_hex).map_err(|_| CredentialError::InvalidPreimage)?;
    let expected_hash =
        hex::decode(&cred.payment_hash_hex).map_err(|_| CredentialError::HashMismatch)?;
    let actual_hash = Sha256::digest(&preimage);
    if !constant_time_eq(actual_hash.as_slice(), &expected_hash) {
        return Err(CredentialError::HashMismatch);
    }

    Ok(())
}

/// Build a `Payment-Receipt` header value for a successful lightning charge.
///
/// `timestamp_iso` must be RFC 3339 (e.g. `"2026-05-23T12:34:56.000Z"`); the
/// caller owns clock reading.
pub fn format_receipt(payment_hash_hex: &str, timestamp_iso: &str) -> String {
    let obj = serde_json::json!({
        "method": "lightning",
        "reference": payment_hash_hex,
        "status": "success",
        "timestamp": timestamp_iso,
    });
    let json = serde_json::to_string(&obj).expect("static schema cannot fail to serialize");
    b64url(json.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"super-secret-test-key";
    const PREIMAGE_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    /// Compute the lowercase-hex sha256 of `PREIMAGE_HEX` at test setup so the
    /// fixture stays internally consistent without a hand-pasted constant.
    fn payment_hash_hex() -> String {
        let bytes = hex::decode(PREIMAGE_HEX).unwrap();
        hex::encode(Sha256::digest(&bytes))
    }

    fn fixture_challenge<'a>(payment_hash: &'a str) -> Challenge<'a> {
        Challenge {
            realm: "api.example.com",
            invoice: "lnbcrt1u1pjmexamplebolt11",
            payment_hash_hex: payment_hash,
            amount_sat: 1000,
            network: Some("regtest"),
            description: None,
            expires: Some("2099-01-01T00:00:00Z"),
            opaque: None,
        }
    }

    #[test]
    fn payment_request_is_canonical_json() {
        let ph = payment_hash_hex();
        let c = fixture_challenge(&ph);
        let s = serialize_payment_request_json(&c);
        // Keys must be alphabetically sorted at every level: amount, currency,
        // methodDetails. Inside methodDetails: invoice, network, paymentHash.
        let amt_pos = s.find("\"amount\"").unwrap();
        let cur_pos = s.find("\"currency\"").unwrap();
        let md_pos = s.find("\"methodDetails\"").unwrap();
        assert!(amt_pos < cur_pos && cur_pos < md_pos);

        let inv_pos = s.find("\"invoice\"").unwrap();
        let net_pos = s.find("\"network\"").unwrap();
        let ph_pos = s.find("\"paymentHash\"").unwrap();
        assert!(inv_pos < net_pos && net_pos < ph_pos);

        // No pretty-printing whitespace.
        assert!(!s.contains('\n'));
        assert!(!s.contains("  "));
    }

    #[test]
    fn challenge_round_trip_through_credential_verify() {
        let ph = payment_hash_hex();
        let c = fixture_challenge(&ph);
        let header = format_challenge(SECRET, &c);
        assert!(header.starts_with("Payment "));
        assert!(header.contains("method=\"lightning\""));
        assert!(header.contains("intent=\"charge\""));

        // Compute what a well-behaved client would echo back.
        let request_serialized = b64url(serialize_payment_request_json(&c).as_bytes());
        let id = compute_challenge_id(
            SECRET,
            c.realm,
            "charge",
            &request_serialized,
            c.expires,
            None,
            c.opaque,
        );
        let credential_obj = serde_json::json!({
            "challenge": {
                "id": id,
                "realm": c.realm,
                "method": "lightning",
                "intent": "charge",
                "request": request_serialized,
                "expires": c.expires,
            },
            "payload": { "preimage": PREIMAGE_HEX },
        });
        let cred_b64 = b64url(credential_obj.to_string().as_bytes());
        let auth_header = format!("Payment {}", cred_b64);

        let parsed = parse_credential(&auth_header).expect("parse");
        assert_eq!(parsed.payment_hash_hex, ph);
        assert_eq!(parsed.preimage_hex, PREIMAGE_HEX);
        verify_credential(&parsed, SECRET, 0).expect("verify");
    }

    #[test]
    fn hmac_mismatch_rejects() {
        let ph = payment_hash_hex();
        let c = fixture_challenge(&ph);
        let request_serialized = b64url(serialize_payment_request_json(&c).as_bytes());
        // Compute id with a different secret to simulate forgery.
        let id = compute_challenge_id(
            b"wrong-secret",
            c.realm,
            "charge",
            &request_serialized,
            c.expires,
            None,
            None,
        );
        let cred = ParsedCredential {
            challenge_id: id,
            realm: c.realm.to_string(),
            method: "lightning".into(),
            intent: "charge".into(),
            request_serialized,
            expires: c.expires.map(|s| s.into()),
            digest: None,
            opaque: None,
            preimage_hex: PREIMAGE_HEX.into(),
            payment_hash_hex: ph,
        };
        assert_eq!(
            verify_credential(&cred, SECRET, 0),
            Err(CredentialError::HmacMismatch)
        );
    }

    #[test]
    fn preimage_hash_mismatch_rejects() {
        let ph = payment_hash_hex();
        let c = fixture_challenge(&ph);
        let request_serialized = b64url(serialize_payment_request_json(&c).as_bytes());
        let id = compute_challenge_id(
            SECRET,
            c.realm,
            "charge",
            &request_serialized,
            c.expires,
            None,
            None,
        );
        let cred = ParsedCredential {
            challenge_id: id,
            realm: c.realm.to_string(),
            method: "lightning".into(),
            intent: "charge".into(),
            request_serialized,
            expires: c.expires.map(|s| s.into()),
            digest: None,
            opaque: None,
            // Wrong preimage (all zeros)
            preimage_hex:
                "0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            payment_hash_hex: ph,
        };
        assert_eq!(
            verify_credential(&cred, SECRET, 0),
            Err(CredentialError::HashMismatch)
        );
    }

    #[test]
    fn expired_challenge_rejects() {
        let ph = payment_hash_hex();
        let mut c = fixture_challenge(&ph);
        c.expires = Some("2000-01-01T00:00:00Z"); // long past
        let request_serialized = b64url(serialize_payment_request_json(&c).as_bytes());
        let id = compute_challenge_id(
            SECRET,
            c.realm,
            "charge",
            &request_serialized,
            c.expires,
            None,
            None,
        );
        let cred = ParsedCredential {
            challenge_id: id,
            realm: c.realm.to_string(),
            method: "lightning".into(),
            intent: "charge".into(),
            request_serialized,
            expires: c.expires.map(|s| s.into()),
            digest: None,
            opaque: None,
            preimage_hex: PREIMAGE_HEX.into(),
            payment_hash_hex: ph,
        };
        // now_unix_ms past the expiry
        let now_ms = 1_700_000_000_000;
        assert_eq!(
            verify_credential(&cred, SECRET, now_ms),
            Err(CredentialError::Expired)
        );
    }

    #[test]
    fn malformed_authorization_inputs_rejected() {
        assert_eq!(
            parse_credential("Bearer abc").unwrap_err(),
            CredentialError::MissingScheme
        );
        assert_eq!(
            parse_credential("Payment !!!not-base64!!!").unwrap_err(),
            CredentialError::InvalidBase64
        );
        // Valid base64 but not JSON
        let bad = b64url(b"not-json");
        assert_eq!(
            parse_credential(&format!("Payment {}", bad)).unwrap_err(),
            CredentialError::InvalidJson
        );
    }

    #[test]
    fn rejects_non_lightning_method() {
        let credential_obj = serde_json::json!({
            "challenge": {
                "id": "x",
                "realm": "r",
                "method": "tempo",
                "intent": "charge",
                "request": b64url(b"{}"),
            },
            "payload": {"preimage": PREIMAGE_HEX},
        });
        let header = format!("Payment {}", b64url(credential_obj.to_string().as_bytes()));
        assert_eq!(
            parse_credential(&header).unwrap_err(),
            CredentialError::InvalidMethod
        );
    }

    #[test]
    fn receipt_round_trip() {
        let ph = payment_hash_hex();
        let r = format_receipt(&ph, "2026-05-23T12:00:00Z");
        let json_bytes = URL_SAFE_NO_PAD.decode(&r).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(v["method"], "lightning");
        assert_eq!(v["reference"], ph);
        assert_eq!(v["status"], "success");
        assert_eq!(v["timestamp"], "2026-05-23T12:00:00Z");
    }

    #[test]
    fn constant_time_eq_handles_length_mismatch() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }
}
