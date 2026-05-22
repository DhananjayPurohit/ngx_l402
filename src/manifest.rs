//! `.well-known/l402` capability manifest.
//!
//! Renders a machine-readable JSON description of every L402-protected
//! location in the running configuration, so agents (and humans) can
//! discover an instance's pricing, accepted payment backends, and route
//! semantics without out-of-band configuration.
//!
//! Decoupled from `ModuleConfig` on purpose: the caller in `lib.rs` walks
//! the per-location configs (which it owns), builds a vector of
//! [`RouteSnapshot`], and hands it here for rendering. Keeps this module
//! free of nginx-FFI internals and trivially unit-testable.

use serde_json::{json, Value};
use std::env;
use std::sync::OnceLock;

/// Cached snapshot of env-driven manifest fields. Populated by
/// [`init_env_snapshot`] from the master process (where env vars are
/// readable) and read at render time from any worker — nginx clears env
/// vars on `fork()` so workers can't query them directly.
#[derive(Debug, Default)]
struct EnvSnapshot {
    service_name: Option<String>,
    service_description: Option<String>,
    service_operator: Option<String>,
    service_contact: Option<String>,
    ln_client_type: String,
    lnurl_address: Option<String>,
    cashu_enabled: bool,
    cashu_mints: Vec<String>,
    cashu_p2pk: bool,
}

static ENV_SNAPSHOT: OnceLock<EnvSnapshot> = OnceLock::new();

/// Cache env-driven manifest fields once, at module init in the master
/// process. Safe to call multiple times — second and later calls are
/// no-ops via [`OnceLock`].
pub fn init_env_snapshot() {
    let _ = ENV_SNAPSHOT.set(EnvSnapshot {
        service_name: env::var("L402_SERVICE_NAME").ok().filter(|s| !s.is_empty()),
        service_description: env::var("L402_SERVICE_DESCRIPTION")
            .ok()
            .filter(|s| !s.is_empty()),
        service_operator: env::var("L402_SERVICE_OPERATOR")
            .ok()
            .filter(|s| !s.is_empty()),
        service_contact: env::var("L402_SERVICE_CONTACT")
            .ok()
            .filter(|s| !s.is_empty()),
        ln_client_type: env::var("LN_CLIENT_TYPE")
            .unwrap_or_else(|_| "LNURL".to_string())
            .to_uppercase(),
        lnurl_address: env::var("LNURL_ADDRESS").ok().filter(|s| !s.is_empty()),
        cashu_enabled: env::var("CASHU_ECASH_SUPPORT")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        cashu_mints: env::var("CASHU_WHITELISTED_MINTS")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        cashu_p2pk: env::var("CASHU_P2PK_MODE")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    });
}

fn env_snapshot() -> &'static EnvSnapshot {
    // Lazy fallback: if init_env_snapshot was never called (shouldn't
    // happen in production, but keeps unit-test-style usage sane),
    // populate from whatever env is visible right now.
    ENV_SNAPSHOT.get_or_init(EnvSnapshot::default)
}

/// Snapshot of a single l402-protected location, taken at manifest-render
/// time (after all `merge_loc_conf` passes have completed).
#[derive(Clone, Debug)]
pub struct RouteSnapshot {
    pub path: String,
    pub price_msat: i64,
    pub macaroon_timeout: i64,
    pub lnurl_addr: Option<String>,
    /// `(max_requests, window_secs)` from `l402_invoice_rate_limit`.
    pub rate_limit: Option<(u32, u64)>,
    pub auto_detect_payment: bool,
    /// True when the operator marked this route with `l402_manifest_hide;` —
    /// exclude from the rendered manifest.
    pub hidden: bool,
}

/// Render the full manifest as a pretty-printed JSON string.
///
/// `routes` is the post-merge snapshot of every location with `l402 on;`.
/// Hidden routes are filtered out here so callers don't have to remember.
pub fn render(routes: &[RouteSnapshot]) -> String {
    let visible: Vec<&RouteSnapshot> = routes.iter().filter(|r| !r.hidden).collect();

    let manifest = json!({
        "version": "1",
        "service": service_block(),
        "payment_methods": payment_methods_block(),
        "routes": visible.iter().map(|r| route_block(r)).collect::<Vec<_>>(),
    });

    // `to_string_pretty` is infallible for `serde_json::Value`; the result
    // is JSON we built, not user input.
    serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| "{}".to_string())
}

fn service_block() -> Value {
    // Service-level metadata is opt-in via env vars. Operators who don't
    // set them get an empty object — the manifest is still valid JSON.
    let snap = env_snapshot();
    let mut block = serde_json::Map::new();
    if let Some(name) = &snap.service_name {
        block.insert("name".to_string(), json!(name));
    }
    if let Some(desc) = &snap.service_description {
        block.insert("description".to_string(), json!(desc));
    }
    if let Some(operator) = &snap.service_operator {
        block.insert("operator".to_string(), json!(operator));
    }
    if let Some(contact) = &snap.service_contact {
        block.insert("contact".to_string(), json!(contact));
    }
    Value::Object(block)
}

fn payment_methods_block() -> Value {
    let snap = env_snapshot();
    let mut methods: Vec<Value> = Vec::new();

    let mut lightning = serde_json::Map::new();
    lightning.insert("type".to_string(), json!("lightning"));
    lightning.insert("backend".to_string(), json!(snap.ln_client_type));
    if snap.ln_client_type.eq_ignore_ascii_case("LNURL") {
        if let Some(addr) = &snap.lnurl_address {
            lightning.insert("address".to_string(), json!(addr));
        }
    }
    methods.push(Value::Object(lightning));

    if snap.cashu_enabled {
        let mut cashu = serde_json::Map::new();
        cashu.insert("type".to_string(), json!("cashu"));
        if !snap.cashu_mints.is_empty() {
            cashu.insert("mints".to_string(), json!(snap.cashu_mints));
        }
        if snap.cashu_p2pk {
            cashu.insert("p2pk_supported".to_string(), json!(true));
            cashu.insert("challenge_header".to_string(), json!("X-Cashu"));
        }
        methods.push(Value::Object(cashu));
    }

    Value::Array(methods)
}

fn route_block(r: &RouteSnapshot) -> Value {
    let mut block = serde_json::Map::new();
    block.insert("path".to_string(), json!(r.path));

    // Price: only emit `static` for now. Dynamic pricing (Redis-backed)
    // is per-key, not knowable at manifest-render time without a redis
    // round-trip per route — out of scope for v1 of the manifest.
    let mut price = serde_json::Map::new();
    price.insert("type".to_string(), json!("static"));
    price.insert("amount_msat".to_string(), json!(r.price_msat));
    block.insert("price".to_string(), Value::Object(price));

    // Caveats the macaroon will carry. Today the access handler binds
    // `RequestPath = <path>` on every challenge; surfacing it here lets
    // agents pre-validate their L402 client logic.
    block.insert(
        "caveats_required".to_string(),
        json!([format!("RequestPath = {}", r.path)]),
    );

    if r.macaroon_timeout > 0 {
        block.insert(
            "macaroon_timeout_secs".to_string(),
            json!(r.macaroon_timeout),
        );
    }

    if let Some(addr) = &r.lnurl_addr {
        // Per-route LNURL override (multi-tenant config). Top-level
        // `payment_methods` reflects the server default; this overrides it.
        block.insert("lnurl_addr".to_string(), json!(addr));
    }

    if let Some((max_requests, window_secs)) = r.rate_limit {
        block.insert(
            "rate_limit".to_string(),
            json!({
                "max_requests": max_requests,
                "window_secs": window_secs,
            }),
        );
    }

    if r.auto_detect_payment {
        block.insert("auto_detect_payment".to_string(), json!(true));
    }

    Value::Object(block)
}

