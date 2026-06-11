use env_logger;
use hex;
use l402_middleware::middleware::L402Middleware;
use l402_middleware::{bolt12, cln, eclair, l402, lnclient, lnd, lnurl, macaroon_util, nwc, utils};
use log::{debug, error, info, warn};
use macaroon::Verifier;
use ngx::core::Buffer;
use ngx::ffi::{
    nginx_version, ngx_array_push, ngx_chain_t, ngx_command_t, ngx_conf_t, ngx_cycle_s,
    ngx_http_discard_request_body, ngx_http_handler_pt, ngx_http_module_t,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_http_request_t, ngx_int_t, ngx_log_s, ngx_module_t,
    ngx_str_t, ngx_uint_t, NGX_CONF_NOARGS, NGX_CONF_TAKE1, NGX_DECLINED, NGX_ERROR, NGX_HTTP_COPY,
    NGX_HTTP_DELETE, NGX_HTTP_GET, NGX_HTTP_HEAD, NGX_HTTP_INTERNAL_SERVER_ERROR, NGX_HTTP_LOCK,
    NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF, NGX_HTTP_MKCOL, NGX_HTTP_MODULE, NGX_HTTP_MOVE,
    NGX_HTTP_NOT_ALLOWED, NGX_HTTP_OPTIONS, NGX_HTTP_PATCH, NGX_HTTP_POST, NGX_HTTP_PROPFIND,
    NGX_HTTP_PROPPATCH, NGX_HTTP_PUT, NGX_HTTP_SRV_CONF, NGX_HTTP_TRACE, NGX_HTTP_UNLOCK,
    NGX_LOG_ERR, NGX_LOG_INFO, NGX_LOG_WARN, NGX_OK,
    NGX_RS_MODULE_SIGNATURE,
};
use ngx::http::{
    HttpModule, HttpModuleLocationConf, HttpModuleMainConf, HttpModuleServerConf, HTTPStatus,
    Merge, MergeConfigError, NgxHttpCoreModule, Request,
};
use ngx::{ngx_log_error, ngx_string};
use r2d2::Pool;
use redis::Client as RedisClient;
use redis::Commands;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::c_char;
use std::ffi::CStr;
use std::os::raw::c_void;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tonic_openssl_lnd::lnrpc;

mod cashu;
mod cashu_redemption_logger;
mod manifest;
mod metrics;
mod payment_detector;
mod payment_page;

static MODULE: OnceLock<L402Module> = OnceLock::new();

/// Cached root key — populated once in the master process during init_module.
/// Workers read from here rather than from the environment, because nginx
/// strips all environment variables from worker processes by default.
static ROOT_KEY_CACHE: OnceLock<Vec<u8>> = OnceLock::new();

/// Read ROOT_KEY from the environment (first call) or from the in-process
/// cache (all subsequent calls, including from worker processes).
/// Panics at startup if the variable is missing or shorter than 32 bytes,
/// preventing silent use of a weak / hardcoded key.
fn require_root_key() -> Vec<u8> {
    ROOT_KEY_CACHE
        .get_or_init(|| {
            let key = std::env::var("ROOT_KEY").unwrap_or_else(|_| {
                panic!(
                    "ROOT_KEY environment variable is not set. \
                     Generate one with: openssl rand -hex 32"
                )
            });
            if key.len() < 32 {
                panic!(
                    "ROOT_KEY must be at least 32 characters long (got {}). \
                     Generate one with: openssl rand -hex 32",
                    key.len()
                );
            }
            key.into_bytes()
        })
        .clone()
}

/// Redact any credentials embedded in a Redis URL before logging.
/// `redis://:secret@host:6379` and `redis://user:secret@host:6379`
/// both become `redis://***@host:6379`. URLs without userinfo are
/// returned unchanged.
fn redact_redis_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.split_once('@') {
        Some((_userinfo, host)) => format!("{}://***@{}", scheme, host),
        None => url.to_string(),
    }
}

/// Registry of l402-enabled locations, populated at config-parse time and
/// drained at `.well-known/l402-services` request time. Each entry holds the
/// location's path and a raw pointer to its `ModuleConfig` — the config
/// lives in nginx's cycle pool, so the pointer remains valid until the
/// next reload, at which point a fresh worker process is started with a
/// new registry.
struct ConfPtr(*const ModuleConfig);
// SAFETY: the ModuleConfig pointers are written once during single-threaded
// config-parse and read-only afterwards. nginx's cycle pool guarantees the
// pointee outlives the registry. There is no aliasing with mutable access.
unsafe impl Send for ConfPtr {}
unsafe impl Sync for ConfPtr {}

struct RouteRegistration {
    path: String,
    conf: ConfPtr,
}

static MANIFEST_REGISTRY: OnceLock<std::sync::Mutex<Vec<RouteRegistration>>> = OnceLock::new();

fn manifest_registry() -> &'static std::sync::Mutex<Vec<RouteRegistration>> {
    MANIFEST_REGISTRY.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Connection pool for Redis. Checked out connections are returned automatically on drop.
/// Pool size is configurable via REDIS_POOL_SIZE (default: cpu_count * 3, min 5, max 50).
static REDIS_POOL: OnceLock<Pool<RedisClient>> = OnceLock::new();

// Cached environment variables — read once at startup, fixed for process lifetime.
// Changing these requires a full restart (SIGHUP will not reload them).
static PREIMAGE_TTL_SECONDS: OnceLock<u64> = OnceLock::new();
static CASHU_TOKEN_TTL_SECONDS: OnceLock<u64> = OnceLock::new();
static PERF_LOG_ENABLED: OnceLock<bool> = OnceLock::new();

/// Single shared tokio runtime for the request handler path.
/// Used by both the 402 challenge generation and Cashu verification code paths.
/// Must be multi-threaded: per-tenant LNURL client creation (get_or_create_lnurl_client)
/// makes HTTPS requests via reqwest which uses spawn_blocking for TLS/DNS operations.
/// A single-threaded runtime has no blocking thread pool, causing those calls to panic.
static HANDLER_RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_handler_runtime() -> &'static Runtime {
    HANDLER_RUNTIME.get_or_init(|| {
        match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("FATAL: failed to create tokio runtime: {}", e);
                std::process::abort();
            }
        }
    })
}

fn perf_log_enabled() -> bool {
    *PERF_LOG_ENABLED.get_or_init(|| {
        std::env::var("L402_PERF_LOG")
            .map(|v| v.trim().to_lowercase() == "true")
            .unwrap_or(false)
    })
}

fn get_preimage_ttl() -> u64 {
    *PREIMAGE_TTL_SECONDS.get_or_init(|| {
        std::env::var("L402_PREIMAGE_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(86400)
    })
}

fn get_cashu_token_ttl() -> u64 {
    *CASHU_TOKEN_TTL_SECONDS.get_or_init(|| {
        std::env::var("L402_CASHU_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(86400)
    })
}

// Cache for LNURL clients - lazy initialization on first use per address
// Uses RwLock instead of Mutex since reads (cache hits) vastly outnumber writes (new client creation)
static LNURL_CLIENT_CACHE: OnceLock<
    tokio::sync::RwLock<HashMap<String, Arc<tokio::sync::Mutex<dyn lnclient::LNClient + Send>>>>,
> = OnceLock::new();

/// Configured LN backend type (`LNURL`, `LND`, `NWC`, ...) captured once at
/// init for use in structured dry-run log lines.
static LN_BACKEND_LABEL: OnceLock<String> = OnceLock::new();

/// Get or create a cached LNURL client for the given address
/// This function is also used by cashu.rs for multi-tenant redemption
pub async fn get_or_create_lnurl_client(
    addr: &str,
) -> Result<Arc<tokio::sync::Mutex<dyn lnclient::LNClient + Send>>, String> {
    let cache = LNURL_CLIENT_CACHE.get_or_init(|| tokio::sync::RwLock::new(HashMap::new()));

    // Fast path: read lock for cache hit (no write contention)
    {
        let cache_guard = cache.read().await;
        if let Some(client) = cache_guard.get(addr) {
            debug!("Using cached LNURL client for: {}", addr);
            return Ok(client.clone());
        }
    }

    // Create a new client
    info!("Creating new LNURL client for: {}", addr);
    let ln_client_config = lnclient::LNClientConfig {
        ln_client_type: "LNURL".to_string(),
        lnd_config: None,
        lnurl_config: Some(lnurl::LNURLOptions {
            address: addr.to_string(),
        }),
        nwc_config: None,
        cln_config: None,
        bolt12_config: None,
        eclair_config: None,
        root_key: require_root_key(),
    };

    match lnurl::LnAddressUrlResJson::new_client(&ln_client_config).await {
        Ok(ln_client) => {
            let client_arc = ln_client;
            // Re-check under write lock to avoid duplicate creation from concurrent requests
            let mut cache_guard = cache.write().await;
            if let Some(existing) = cache_guard.get(addr) {
                return Ok(existing.clone());
            }
            cache_guard.insert(addr.to_string(), client_arc.clone());
            info!("✅ Cached LNURL client for: {}", addr);
            Ok(client_arc)
        }
        Err(e) => {
            error!("❌ Failed to create LNURL client for {}: {:?}", addr, e);
            Err(format!("Failed to create LNURL client: {:?}", e))
        }
    }
}

/// Fast-fail pre-check: returns true if the preimage is already known-used.
/// This is NOT the authoritative admission gate — it only avoids wasted CPU
/// on obvious replays. The atomic SET NX EX in store_preimage_as_used() is
/// the true gate and closes the TOCTOU window between concurrent workers.
/// Fails open (returns false) if Redis is unavailable.
fn is_preimage_used(preimage: &[u8]) -> bool {
    let Some(pool) = REDIS_POOL.get() else {
        return false;
    };
    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let redis_key = preimage_redis_key(preimage);
    conn.exists::<_, bool>(&redis_key).unwrap_or(false)
}

/// Atomically store a preimage as used via SET NX EX (single round-trip).
/// Returns Ok(true) if stored successfully (first use), Ok(false) if already existed (race with another worker).
/// Called ONLY after successful verification to avoid burning preimages on transient failures.
fn store_preimage_as_used(preimage: &[u8]) -> Result<bool, String> {
    let pool = REDIS_POOL.get().ok_or("Redis not configured")?;

    let mut conn = pool
        .get()
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let redis_key = preimage_redis_key(preimage);
    let ttl = get_preimage_ttl();

    // SET NX EX — atomic store-if-absent with TTL
    match redis::cmd("SET")
        .arg(&redis_key)
        .arg("used")
        .arg("NX")
        .arg("EX")
        .arg(ttl)
        .query::<Option<String>>(&mut *conn)
    {
        Ok(Some(_)) => {
            info!("✅ Preimage stored as used (TTL: {}s)", ttl);
            Ok(true)
        }
        Ok(None) => {
            // Another worker stored it between our EXISTS check and this SET NX — that's fine
            Ok(false)
        }
        Err(e) => Err(format!("Redis SET NX failed: {}", e)),
    }
}

/// Helper: compute the Redis key for a preimage (single SHA256 hash, reusable).
fn preimage_redis_key(preimage: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    format!("l402:preimage:{}", hex::encode(hasher.finalize()))
}

/// Check if a Cashu token has been used before (replay attack prevention).
/// Returns true if token is already used, false if it's new.
/// Fails open (returns false) if Redis is unavailable.
pub fn is_cashu_token_used(token: &str) -> bool {
    let Some(pool) = REDIS_POOL.get() else {
        warn!("⚠️ Redis not configured - Cashu token replay protection limited to memory");
        return false;
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!(
                "❌ Failed to get Redis connection for Cashu token check: {}",
                e
            );
            return false; // fail-open
        }
    };

    let redis_key = cashu_token_redis_key(token);

    match conn.exists::<_, bool>(&redis_key) {
        Ok(exists) => {
            if exists {
                warn!("⚠️ Cashu token replay attack detected");
            }
            exists
        }
        Err(e) => {
            error!("❌ Failed to check Cashu token in Redis: {}", e);
            false // fail-open
        }
    }
}

/// Atomically store a Cashu token as used via SET NX EX (single round-trip).
/// Called ONLY after successful verification to avoid burning tokens on transient failures.
pub fn store_cashu_token_as_used(token: &str) -> Result<bool, String> {
    let pool = REDIS_POOL.get().ok_or("Redis not configured")?;

    let mut conn = pool
        .get()
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let redis_key = cashu_token_redis_key(token);
    let ttl = get_cashu_token_ttl();

    match redis::cmd("SET")
        .arg(&redis_key)
        .arg("used")
        .arg("NX")
        .arg("EX")
        .arg(ttl)
        .query::<Option<String>>(&mut *conn)
    {
        Ok(Some(_)) => {
            info!("✅ Cashu token stored as used (TTL: {}s)", ttl);
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(e) => Err(format!("Redis SET NX failed: {}", e)),
    }
}

/// Helper: compute the Redis key for a Cashu token.
fn cashu_token_redis_key(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("l402:cashu_token:{}", hex::encode(hasher.finalize()))
}

/// Look up a previously-cached preimage for a settled invoice.
/// Key: `l402:settled:<payment_hash_hex>` → `<preimage_hex>`
pub fn get_cached_settled_preimage(payment_hash: &[u8]) -> Option<Vec<u8>> {
    let pool = REDIS_POOL.get()?;
    let mut conn = pool.get().ok()?;
    let hash_hex = hex::encode(payment_hash);
    let redis_key = format!("l402:settled:{}", hash_hex);
    let stored: Option<String> = conn.get(&redis_key).unwrap_or(None);
    stored.and_then(|h| hex::decode(h).ok())
}

/// Cache a preimage for a settled invoice with TTL (same as preimage TTL).
pub fn cache_settled_preimage(payment_hash: &[u8], preimage: &[u8]) -> Result<(), String> {
    let pool = REDIS_POOL.get().ok_or("Redis not configured")?;
    let mut conn = pool
        .get()
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let hash_hex = hex::encode(payment_hash);
    let preimage_hex = hex::encode(preimage);
    let redis_key = format!("l402:settled:{}", hash_hex);

    let ttl_seconds = std::env::var("L402_PREIMAGE_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(86400);

    conn.set_ex::<_, _, ()>(&redis_key, preimage_hex, ttl_seconds)
        .map_err(|e| format!("Failed to cache settled preimage: {}", e))?;

    info!("✅ Cached settled preimage for payment_hash {}", &hash_hex[..16]);
    Ok(())
}

/// Parse the macaroon from an L402 authorization string and return
/// the raw 32-byte payment hash embedded in its identifier.

/// Accepts both formats:
///   - `L402 <macaroon_b64>:<preimage_hex>`  (classic)
///   - `L402 <macaroon_b64>`                 (auto-detect)
pub fn extract_payment_hash_from_auth_str(auth_str: &str) -> Result<Vec<u8>, String> {
    let token = auth_str
        .trim()
        .trim_start_matches("L402 ")
        .trim_start_matches("Bearer ");

    // Take only the macaroon part (before any ':')
    let macaroon_b64 = token.split(':').next().unwrap_or(token);

    let mac = utils::get_macaroon_from_string(macaroon_b64.to_string())
        .map_err(|e| format!("Failed to deserialize macaroon: {}", e))?;

    // The identifier holds the raw payment-hash bytes (usually 32 bytes).
    // We extract the raw hash here for the node lookup by stripping the leading 
    // 0xff sentinel if the identifier length is 33 bytes.
    let id_bytes = mac.identifier().0.clone();

    let hash_bytes: Vec<u8> = if id_bytes.len() == 33 && id_bytes[0] == 0xff {
        // Drop the 0xff version byte to get the 32-byte hash
        id_bytes[1..].to_vec()
    } else if id_bytes.len() == 32 {
        id_bytes.clone()
    } else {
        // Fallback for unexpected lengths: skip leading 0xff until we find 32 bytes
        let stripped: Vec<u8> = id_bytes
            .iter()
            .copied()
            .skip_while(|&b| b == 0xff)
            .collect();
        
        if stripped.len() == 32 {
            stripped
        } else {
            return Err(format!(
                "Unexpected identifier length: {} bytes (expected 32 after stripping 0xff)",
                stripped.len()
            ));
        }
    };

    Ok(hash_bytes)
}

pub struct L402Module {
    middleware: L402Middleware,
}

impl L402Module {
    pub async fn new() -> Self {
        info!("🚀 Creating new L402Module");

        // Initialize Redis client if URL is configured
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            // Pool size: configurable via REDIS_POOL_SIZE.
            // Default heuristic: nginx workers are CPU-bound, Redis ops are fast,
            // so 3 connections per logical CPU is plenty. Clamped to [5, 50].
            let cpu_count = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4); // Fall back to 4 if detection fails
            let default_pool_size = (cpu_count * 3).clamp(5, 50) as u32;
            let pool_size = std::env::var("REDIS_POOL_SIZE")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(default_pool_size);

            match RedisClient::open(redis_url.clone()) {
                Ok(manager) => match Pool::builder().max_size(pool_size).build(manager) {
                    Ok(pool) => {
                        if REDIS_POOL.set(pool).is_ok() {
                            info!(
                                "✅ Redis connection pool ready (max_size={}) at {}",
                                pool_size,
                                redact_redis_url(&redis_url)
                            );
                        } else {
                            error!("❌ Failed to register Redis pool in OnceLock");
                        }
                    }
                    Err(e) => error!("❌ Failed to build Redis connection pool: {}", e),
                },
                Err(e) => error!("❌ Failed to create Redis client: {}", e),
            }
        } else {
            info!("ℹ️ No REDIS_URL configured — Redis features disabled");
        }

        // Get environment variables
        let ln_client_type =
            std::env::var("LN_CLIENT_TYPE").unwrap_or_else(|_| "LNURL".to_string());
        info!("⚡ Using LN client type: {}", ln_client_type);

        let ln_client_config = match ln_client_type.as_str() {
            "LNURL" => {
                info!("🔧 Configuring LNURL client");
                let address =
                    std::env::var("LNURL_ADDRESS").unwrap_or_else(|_| "lnurl_address".to_string());
                info!("🔗 Using LNURL address: {}", address);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: Some(lnurl::LNURLOptions { address }),
                    nwc_config: None,
                    cln_config: None,
                    bolt12_config: None,
                    eclair_config: None,
                    root_key: require_root_key(),
                }
            }
            "LND" => {
                info!("🔧 Configuring LND client");

                // Check if using LNC (Lightning Node Connect)
                let lnc_pairing_phrase = std::env::var("LNC_PAIRING_PHRASE").ok();
                let lnc_mailbox_server = std::env::var("LNC_MAILBOX_SERVER").ok();

                // Configure based on connection type
                let lnd_options = if lnc_pairing_phrase.is_some() {
                    // LNC mode - only pairing phrase needed, no cert/macaroon required
                    info!("🔗 Using LNC (Lightning Node Connect) mode");
                    if let Some(ref phrase) = lnc_pairing_phrase {
                        info!(
                            "📱 LNC pairing phrase configured (length: {})",
                            phrase.len()
                        );
                    }
                    if let Some(ref server) = lnc_mailbox_server {
                        info!("📮 LNC mailbox server: {}", server);
                    }
                    lnd::LNDOptions {
                        address: None,
                        macaroon_file: None,
                        cert_file: None,
                        socks5_proxy: None,
                        lnc_pairing_phrase,
                        lnc_mailbox_server,
                    }
                } else {
                    // Traditional LND mode - all required
                    info!("⚡ Using traditional LND mode");
                    let address = std::env::var("LND_ADDRESS")
                        .unwrap_or_else(|_| "localhost:10009".to_string());
                    info!("🔗 Using LND address: {}", address);
                    let socks5_proxy = std::env::var("SOCKS5_PROXY").ok();
                    if let Some(ref proxy) = socks5_proxy {
                        info!("🔒 Using SOCKS5 proxy: {}", proxy);
                    }
                    lnd::LNDOptions {
                        address: Some(address),
                        macaroon_file: Some(
                            std::env::var("MACAROON_FILE_PATH")
                                .unwrap_or_else(|_| "admin.macaroon".to_string()),
                        ),
                        cert_file: Some(
                            std::env::var("CERT_FILE_PATH")
                                .unwrap_or_else(|_| "tls.cert".to_string()),
                        ),
                        socks5_proxy,
                        lnc_pairing_phrase: None,
                        lnc_mailbox_server: None,
                    }
                };

                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: Some(lnd_options),
                    lnurl_config: None,
                    nwc_config: None,
                    cln_config: None,
                    bolt12_config: None,
                    eclair_config: None,
                    root_key: require_root_key(),
                }
            }
            "NWC" => {
                info!("🔧 Configuring NWC client");
                let uri = std::env::var("NWC_URI").unwrap_or_else(|_| "nwc_uri".to_string());
                // NOTE: never log the full NWC URI — it contains `secret=<hex>`,
                // the wallet connection secret. Log only the scheme/relay shape.
                info!("🔗 NWC client configured (URI redacted)");
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: None,
                    cln_config: None,
                    nwc_config: Some(nwc::NWCOptions { uri }),
                    bolt12_config: None,
                    eclair_config: None,
                    root_key: require_root_key(),
                }
            }
            "CLN" => {
                info!("🔧 Configuring CLN client");
                let lightning_dir = std::env::var("CLN_LIGHTNING_RPC_FILE_PATH")
                    .unwrap_or_else(|_| "CLN_LIGHTNING_RPC_FILE_PATH".to_string());
                info!("🖾 Using CLN LIGHTNING RPC FILE PATH: {}", lightning_dir);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: None,
                    nwc_config: None,
                    cln_config: Some(cln::CLNOptions { lightning_dir }),
                    bolt12_config: None,
                    eclair_config: None,
                    root_key: require_root_key(),
                }
            }
            "BOLT12" => {
                info!("🔧 Configuring BOLT12 client");
                let offer =
                    std::env::var("BOLT12_OFFER").unwrap_or_else(|_| "bolt12_offer".to_string());
                let lightning_dir = std::env::var("CLN_LIGHTNING_RPC_FILE_PATH")
                    .unwrap_or_else(|_| "CLN_LIGHTNING_RPC_FILE_PATH".to_string());
                info!("⚡ Using BOLT12 Offer: {}", offer);
                info!(
                    "🖾 Using CLN LIGHTNING RPC FILE PATH for BOLT12: {}",
                    lightning_dir
                );
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: None,
                    nwc_config: None,
                    // CLN is still required to fetch invoices from the reusable offer.
                    cln_config: Some(cln::CLNOptions {
                        lightning_dir: lightning_dir.clone(),
                    }),
                    bolt12_config: Some(bolt12::Bolt12Options {
                        offer,
                        lightning_dir,
                    }),
                    eclair_config: None,
                    root_key: require_root_key(),
                }
            }
            "ECLAIR" => {
                info!("🔧 Configuring ECLAIR client");
                let address = std::env::var("ECLAIR_ADDRESS")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string());
                let password =
                    std::env::var("ECLAIR_PASSWORD").unwrap_or_else(|_| "password".to_string());
                info!("🔗 Using ECLAIR address: {}", address);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: None,
                    nwc_config: None,
                    cln_config: None,
                    bolt12_config: None,
                    eclair_config: Some(eclair::EclairOptions {
                        api_url: address,
                        password,
                    }),
                    root_key: require_root_key(),
                }
            }
            _ => {
                warn!("⚠️ Unknown client type, defaulting to LNURL");
                let address =
                    std::env::var("LNURL_ADDRESS").unwrap_or_else(|_| "lnurl_address".to_string());
                info!("🔗 Using LNURL address: {}", address);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: Some(lnurl::LNURLOptions { address }),
                    nwc_config: None,
                    cln_config: None,
                    bolt12_config: None,
                    eclair_config: None,
                    root_key: require_root_key(),
                }
            }
        };

        info!("🔧 Creating L402 middleware");
        let middleware = L402Middleware::new_l402_middleware(
            ln_client_config.clone(),
            Arc::new(move |_| {
                Box::pin(async move {
                    0 // Placeholder value, declaring for type inference
                })
            }),
            Arc::new(|req| vec![format!("RequestPath = {}", req.uri().path())]),
        )
        .await
        .expect("Failed to create middleware");

        Self { middleware }
    }

    pub async fn get_l402_header(
        &self,
        mut caveats: Vec<String>,
        amount_msat: i64,
        timeout_secs: i64,
        lnurl_addr: Option<String>,
    ) -> Option<String> {
        let ln_invoice = lnrpc::Invoice {
            value_msat: amount_msat,
            memo: l402::L402_HEADER.to_string(),
            ..Default::default()
        };

        debug!("Invoice value: {} msat", amount_msat);

        // If a per-location LNURL address is provided, use cached LNURL client
        // Otherwise use the global ln_client from middleware
        let (invoice, payment_hash) = if let Some(ref addr) = lnurl_addr {
            debug!("Using per-location LNURL address for invoice: {}", addr);

            match get_or_create_lnurl_client(addr).await {
                Ok(ln_client) => {
                    let ln_client_conn = lnclient::LNClientConn { ln_client };
                    match ln_client_conn.generate_invoice(ln_invoice).await {
                        Ok(result) => result,
                        Err(e) => {
                            error!("❌ Error generating invoice via LNURL {}: {:?}", addr, e);
                            return None;
                        }
                    }
                }
                Err(e) => {
                    error!("❌ Error getting LNURL client for {}: {}", addr, e);
                    return None;
                }
            }
        } else {
            let ln_client_conn = lnclient::LNClientConn {
                ln_client: self.middleware.ln_client.clone(),
            };
            match ln_client_conn.generate_invoice(ln_invoice).await {
                Ok(result) => result,
                Err(e) => {
                    error!("❌ Error generating invoice: {:?}", e);
                    return None;
                }
            }
        };

        debug!("📜 Generated invoice: {}", invoice);

        // Only add expiry time caveat if timeout_secs > 0
        if timeout_secs > 0 {
            let expiry = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
                + timeout_secs;
            caveats.push(format!("ExpiresAt = {}", expiry));
        }

        match macaroon_util::get_macaroon_as_string(
            payment_hash,
            caveats,
            self.middleware.root_key.clone(),
        ) {
            Ok(macaroon_string) => {
                let header_value = format!(
                    "L402 macaroon=\"{}\", invoice=\"{}\"",
                    macaroon_string, invoice
                );
                debug!("🍪 Generated macaroon header: {}", header_value);
                Some(header_value)
            }
            Err(error) => {
                error!("❌ Error generating macaroon: {}", error);
                None
            }
        }
    }

    pub async fn verify_cashu_token(
        &self,
        token: &str,
        amount_msat: i64,
        lnurl_addr: Option<String>,
    ) -> Result<bool, String> {
        // Check if P2PK mode is enabled (use initialized state, not env vars)
        if cashu::is_p2pk_mode_enabled() {
            info!("🔐 Using P2PK local verification mode");
            cashu::verify_cashu_token_p2pk(token, amount_msat, lnurl_addr).await
        } else {
            info!("💰 Using standard Cashu verification (with mint receive)");
            cashu::verify_cashu_token(token, amount_msat, lnurl_addr).await
        }
    }

    pub fn get_cashu_payment_request(&self, amount_msat: i64) -> Option<String> {
        // Check if P2PK mode is enabled (use initialized state, not env vars)
        if !cashu::is_p2pk_mode_enabled() {
            return None;
        }

        // Get whitelisted mints
        if let Some(whitelisted_mints) = cashu::get_whitelisted_mints() {
            match cashu::generate_payment_request(amount_msat, whitelisted_mints) {
                Ok(req) => {
                    info!(
                        "✅ Generated X-Cashu payment request (P2PK): {}",
                        &req[..50.min(req.len())]
                    );
                    Some(req)
                }
                Err(e) => {
                    error!("❌ Failed to generate payment request: {}", e);
                    None
                }
            }
        } else {
            error!("❌ No whitelisted mints configured for P2PK mode");
            None
        }
    }

    /// Fetch per-path price (`<path>` key) and LNURL override (`lnurl:<path>` key)
    /// in a single Redis pipeline. Two GETs become one round-trip.
    /// Returns `(0, None)` if Redis is unavailable or the keys are missing.
    pub fn get_dynamic_config(&self, path: &str) -> (i64, Option<String>) {
        let Some(pool) = REDIS_POOL.get() else {
            return (0, None);
        };
        let Ok(mut conn) = pool.get() else {
            return (0, None);
        };
        let lnurl_key = format!("lnurl:{}", path);
        match redis::pipe()
            .get(path)
            .get(&lnurl_key)
            .query::<(Option<i64>, Option<String>)>(&mut *conn)
        {
            Ok((price, lnurl)) => (price.unwrap_or(0), lnurl),
            Err(_) => (0, None),
        }
    }
}

impl HttpModule for L402Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_l402_module) }
    }

    unsafe extern "C" fn preconfiguration(_cf: *mut ngx_conf_t) -> ngx_int_t {
        // Clear the manifest registry at the start of each config parse.
        // On `nginx -s reload`, the master parses the new config; without
        // this clear we'd accumulate stale (path, conf_ptr) entries from
        // the previous cycle whose pool memory has been freed — reading
        // them later from /.well-known/l402-services is a use-after-free.
        if let Ok(mut reg) = manifest_registry().lock() {
            reg.clear();
        }
        NGX_OK as ngx_int_t
    }

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        info!("🚀 Initializing L402 module handler");
        let cmcf: *mut ngx::ffi::ngx_http_core_main_conf_t = NgxHttpCoreModule::main_conf_mut(&*cf).expect("http core main conf") as *mut _;
        let h = ngx_array_push(
            &mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers,
        ) as *mut ngx_http_handler_pt;

        if h.is_null() {
            return NGX_ERROR as ngx_int_t;
        }
        // set an access phase handler for l402 (after location matching and rewrite)
        *h = Some(l402_access_handler_wrapper);
        NGX_OK as ngx_int_t
    }
}

unsafe impl HttpModuleLocationConf for L402Module {
    type LocationConf = ModuleConfig;
}

unsafe impl HttpModuleMainConf for L402Module {
    type MainConf = ();
}

unsafe impl HttpModuleServerConf for L402Module {
    type ServerConf = ();
}

#[derive(Debug, Default)]
pub struct ModuleConfig {
    enable: bool,
    amount_msat: i64,
    macaroon_timeout: i64,
    lnurl_addr: Option<String>,
    // (max_requests, window_secs): e.g. (5, 60) means 5 invoices per minute per IP per route.
    // None means rate limiting is disabled for this location.
    invoice_rate_limit: Option<(u32, u64)>,
    auto_detect_payment: bool,
    // Shadow mode: evaluate pricing and generate challenges but never block
    // the request. Used for safe production rollouts. `None` means unset
    // (inherit from parent scope); `Some(false)` explicitly turns it off and
    // stops inheritance.
    dry_run: Option<bool>,
    // When set via `l402_manifest_hide;`, this route is excluded from the
    // `.well-known/l402-services` capability manifest. The route is still gated as
    // normal — this just makes it not discoverable.
    manifest_hidden: bool,
}

pub static mut NGX_HTTP_L402_COMMANDS: [ngx_command_t; 11] = [
    ngx_command_t {
        name: ngx_string!("l402"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_amount_msat_default"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_amount_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_macaroon_timeout"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_timeout_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_lnurl_addr"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_lnurl_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_invoice_rate_limit"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_invoice_rate_limit_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_auto_detect_payment"),
        type_: (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_auto_detect_payment_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_dry_run"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_dry_run_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_metrics"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS) as ngx_uint_t,
        set: Some(ngx_http_l402_metrics_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_manifest"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS) as ngx_uint_t,
        set: Some(ngx_http_l402_manifest_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_manifest_hide"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS) as ngx_uint_t,
        set: Some(ngx_http_l402_manifest_hide_set),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

pub static NGX_HTTP_L402_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(L402Module::preconfiguration),
    postconfiguration: Some(L402Module::postconfiguration),
    create_main_conf: Some(L402Module::create_main_conf),
    init_main_conf: Some(L402Module::init_main_conf),
    create_srv_conf: Some(L402Module::create_srv_conf),
    merge_srv_conf: Some(L402Module::merge_srv_conf),
    create_loc_conf: Some(L402Module::create_loc_conf),
    merge_loc_conf: Some(L402Module::merge_loc_conf),
};

// Generate the `ngx_modules` table with exported modules.
// This feature is required to build a 'cdylib' dynamic module outside of the NGINX buildsystem.
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_l402_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), no_mangle)]
pub static mut ngx_http_l402_module: ngx_module_t = ngx_module_t {
    ctx_index: ngx_uint_t::MAX,
    index: ngx_uint_t::MAX,
    name: std::ptr::null_mut(),
    spare0: 0,
    spare1: 0,
    version: nginx_version as ngx_uint_t,
    signature: NGX_RS_MODULE_SIGNATURE.as_ptr() as *const c_char,

    ctx: &NGX_HTTP_L402_MODULE_CTX as *const _ as *mut c_void,
    commands: unsafe { &NGX_HTTP_L402_COMMANDS[0] as *const _ as *mut _ },
    type_: NGX_HTTP_MODULE as usize,

    init_master: None,
    init_module: Some(init_module as unsafe extern "C" fn(*mut ngx_cycle_s) -> isize),
    init_process: None,
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

impl Merge for ModuleConfig {
    fn merge(&mut self, prev: &ModuleConfig) -> Result<(), MergeConfigError> {
        if prev.enable {
            self.enable = true;
        };
        if prev.amount_msat > 0 && self.amount_msat == 0 {
            self.amount_msat = prev.amount_msat;
        }
        if prev.macaroon_timeout > 0 && self.macaroon_timeout == 0 {
            self.macaroon_timeout = prev.macaroon_timeout;
        }
        if self.lnurl_addr.is_none() && prev.lnurl_addr.is_some() {
            self.lnurl_addr = prev.lnurl_addr.clone();
        }
        if self.invoice_rate_limit.is_none() {
            self.invoice_rate_limit = prev.invoice_rate_limit;
        }
        if prev.auto_detect_payment {
            self.auto_detect_payment = true;
        }
        // Standard "child wins if set" merge — `l402_dry_run off;` in an inner
        // location overrides `l402_dry_run on;` on the outer scope.
        if self.dry_run.is_none() {
            self.dry_run = prev.dry_run;
        }
        if prev.manifest_hidden {
            self.manifest_hidden = true;
        }
        Ok(())
    }
}


/// Map nginx's `r->method` bitmask to the canonical uppercase string used in
/// the `RequestMethod` macaroon caveat. Falls back to `"UNKNOWN"` for methods
/// nginx didn't recognise; both sides of the protocol see the same fallback,
/// so the binding still excludes cross-method replay between recognised
/// methods (the only ones a typical client will use).
fn method_caveat_value(method: u32) -> &'static str {
    match method {
        m if m == NGX_HTTP_GET => "GET",
        m if m == NGX_HTTP_HEAD => "HEAD",
        m if m == NGX_HTTP_POST => "POST",
        m if m == NGX_HTTP_PUT => "PUT",
        m if m == NGX_HTTP_DELETE => "DELETE",
        m if m == NGX_HTTP_OPTIONS => "OPTIONS",
        m if m == NGX_HTTP_PATCH => "PATCH",
        m if m == NGX_HTTP_TRACE => "TRACE",
        m if m == NGX_HTTP_MKCOL => "MKCOL",
        m if m == NGX_HTTP_COPY => "COPY",
        m if m == NGX_HTTP_MOVE => "MOVE",
        m if m == NGX_HTTP_PROPFIND => "PROPFIND",
        m if m == NGX_HTTP_PROPPATCH => "PROPPATCH",
        m if m == NGX_HTTP_LOCK => "LOCK",
        m if m == NGX_HTTP_UNLOCK => "UNLOCK",
        _ => "UNKNOWN",
    }
}
/// Extract the raw macaroon (base64) and invoice (bolt11) strings from a
/// `WWW-Authenticate` header value of the form:
///   `L402 macaroon="<b64>", invoice="<bolt11>"`
fn parse_l402_header_value(header: &str) -> Option<(String, String)> {
    let mac = header.split("macaroon=\"").nth(1)?.split('"').next()?.to_string();
    let inv = header.split("invoice=\"").nth(1)?.split('"').next()?.to_string();
    Some((mac, inv))
}

/// Send a full HTTP response (status + body) from within an access-phase
/// handler. Mirrors the pattern used by `l402_metrics_content_handler`.
///
/// Returns the value to pass straight back to nginx (an `ngx_int_t` / `isize`).
///
/// # Safety
/// `r` must be the non-null, valid request pointer supplied by nginx.
unsafe fn send_html_response(r: *mut ngx_http_request_t, status: u16, body: String) -> isize {
    let rc = unsafe { ngx_http_discard_request_body(r) };
    if rc != NGX_OK as ngx_int_t {
        return rc as isize;
    }

    let body_len = body.len();
    let req = unsafe { Request::from_ngx_http_request(r) };
    let pool = req.pool();

    let Some(mut buf) = pool.create_buffer_from_str(&body) else {
        return NGX_HTTP_INTERNAL_SERVER_ERROR as isize;
    };
    buf.set_last_buf(true);
    buf.set_last_in_chain(true);

    let chain = pool.alloc_type::<ngx_chain_t>();
    if chain.is_null() {
        return NGX_HTTP_INTERNAL_SERVER_ERROR as isize;
    }
    unsafe {
        (*chain).buf = buf.as_ngx_buf_mut();
        (*chain).next = std::ptr::null_mut();
    }

    req.set_status(HTTPStatus(status as usize));
    req.set_content_length_n(body_len);
    let _ = req.add_header_out("Content-Type", "text/html; charset=utf-8");

    let send_status = req.send_header();
    if send_status.0 == NGX_ERROR as ngx_int_t
        || send_status.0 > NGX_OK as ngx_int_t
        || req.header_only()
    {
        return send_status.0 as isize;
    }

    unsafe { req.output_filter(&mut *chain).0 as isize }
}


// Per-worker scratch slot used by `l402_access_handler` to report *which*
// payment method satisfied a successful verification. The wrapper consumes it
// only in enforce mode (after the dry-run early return) so shadow traffic
// doesn't pollute `l402_payments_lightning_total` / `l402_payments_cashu_total`
// and the invariant `valid = lightning + cashu` holds.
#[derive(Clone, Copy)]
enum PaymentMethod {
    Lightning,
    Cashu,
}

thread_local! {
    static LAST_PAYMENT_METHOD: std::cell::Cell<Option<PaymentMethod>> =
        const { std::cell::Cell::new(None) };
}

// SAFETY: This function is an Nginx access-phase handler registered via
// `postconfiguration`. Nginx guarantees that `request`, `request->connection`,
// `request->connection->log`, and `request->loc_conf` are valid, non-null
// pointers for the handler's lifetime.
pub unsafe extern "C" fn l402_access_handler_wrapper(request: *mut ngx_http_request_t) -> isize {
    let handler_start = Instant::now();

    // SAFETY: `request` is guaranteed non-null by Nginx for access-phase handlers.
    let r = unsafe { &mut *request };

    // SAFETY: `connection` and `log` are guaranteed valid by Nginx for the
    // lifetime of the request.
    let log = unsafe { &mut *(*r.connection).log };
    let log_ref = log as *mut ngx_log_s;

    // Check if L402 is enabled for this location
    let (
        auth_header,
        uri,
        method,
        amount_msat,
        macaroon_timeout,
        lnurl_addr,
        invoice_rate_limit,
        auto_detect_payment,
        dry_run,
    ) = unsafe {
        // NOTE: `authorization` can be null — not every request carries the header.
        let auth_header = if !r.headers_in.authorization.is_null() {
            // SAFETY: `authorization` checked non-null; Nginx guarantees
            // `value.data` is a valid C string for the header lifetime.
            Some(
                CStr::from_ptr((*r.headers_in.authorization).value.data as *const c_char)
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        } else {
            None
        };

        let uri = r.uri.to_string();
        let method = r.method as u32;

        // SAFETY: `loc_conf` is guaranteed valid by Nginx; `ctx_index` is set
        // during module registration and is within bounds.
        let loc_conf = r.loc_conf;
        // SAFETY: The config slot is allocated by `create_loc_conf` and merged
        // by Nginx before the access phase runs.
        let conf =
            &*((*loc_conf.offset(ngx_http_l402_module.ctx_index as isize)) as *const ModuleConfig);

        if !conf.enable {
            ngx_log_error!(NGX_LOG_INFO, log_ref, "L402 is disabled for this location");
            return NGX_DECLINED as isize;
        }

        let amount_msat = conf.amount_msat;
        if amount_msat <= 0 {
            ngx_log_error!(
                NGX_LOG_INFO,
                log_ref,
                "L402 amount_msat is not set or invalid"
            );
            return 500;
        }

        let macaroon_timeout = conf.macaroon_timeout;
        if macaroon_timeout < 0 {
            ngx_log_error!(NGX_LOG_INFO, log_ref, "L402 macaroon_timeout is invalid");
            return 500;
        }

        let lnurl_addr = conf.lnurl_addr.clone();
        let invoice_rate_limit = conf.invoice_rate_limit;
        let auto_detect_payment = conf.auto_detect_payment;
        let dry_run = conf.dry_run.unwrap_or(false);

        (
            auth_header,
            uri.clone(),
            method,
            amount_msat,
            macaroon_timeout,
            lnurl_addr,
            invoice_rate_limit,
            auto_detect_payment,
            dry_run,
        )
    };

    // Bind the macaroon to the exact request URI and HTTP method so a
    // token paid for `GET /v1/data` can't be replayed against `POST /v1/data`.
    // NOTE: no path normalization — stripping .html / trailing-slash suffixes
    // would widen the macaroon scope to the parent directory, allowing a token
    // issued for /docs/page.html to be reused against /docs/secret (CWE-285).
    let request_path = uri.clone();
    let request_method = method_caveat_value(method);
    let caveats = vec![
        format!("RequestPath = {}", request_path),
        format!("RequestMethod = {}", request_method),
    ];

    let module = match MODULE.get() {
        Some(m) => m,
        None => {
            error!("Module not initialized — returning 500");
            return 500;
        }
    };

    // Fetch dynamic config (price + lnurl) from Redis only when it can affect the
    // outcome: the Cashu auth path needs the per-path amount + lnurl for verification,
    // and the no-auth path needs them for the 402 challenge. The L402 macaroon path
    // uses neither, so we skip the Redis round-trip entirely for it.
    let needs_dynamic_config = match auth_header.as_deref() {
        Some(s) => s.starts_with("Cashu "),
        None => true,
    };

    let (final_amount, final_lnurl_addr, price_source) = if needs_dynamic_config {
        let redis_start = Instant::now();
        let (dynamic_amount, dynamic_lnurl) = module.get_dynamic_config(&request_path);
        if perf_log_enabled() {
            debug!(
                "perf: stage=redis_dynamic_config duration_us={} path={}",
                redis_start.elapsed().as_micros(),
                request_path
            );
        }
        let (amount, src) = if dynamic_amount > 0 {
            (dynamic_amount, "dynamic")
        } else {
            (amount_msat, "static")
        };
        (amount, dynamic_lnurl.or(lnurl_addr), src)
    } else {
        // L402 macaroon path skips the Redis lookup entirely — there is no
        // dynamic price to compare against, so the source is "static".
        (amount_msat, lnurl_addr, "static")
    };

    metrics::inc(&metrics::L402_REQUESTS_TOTAL);
    let auth_present = auth_header.is_some();
    let auth_start = Instant::now();
    let result = l402_access_handler(
        auth_header,
        uri,
        method,
        final_amount,
        caveats.clone(),
        final_lnurl_addr.clone(),
        auto_detect_payment,
    );
    let auth_duration = auth_start.elapsed();

    if perf_log_enabled() {
        debug!(
            "perf: stage=auth_check duration_us={} path={}",
            auth_duration.as_micros(),
            request_path
        );
    }

    if dry_run {
        return handle_dry_run_passthrough(
            request,
            log_ref,
            module,
            &request_path,
            final_amount,
            price_source,
            final_lnurl_addr,
            macaroon_timeout,
            caveats,
            result,
            auth_present,
            invoice_rate_limit,
        );
    }

    // Enforce-mode outcome counters. Deliberately skipped above for dry-run
    // so shadow traffic doesn't pollute enforce-mode SLO dashboards. The
    // per-method counters are consumed from the thread-local set by
    // `l402_access_handler` so the invariant `valid = lightning + cashu`
    // holds and shadow traffic never ticks them.
    match result {
        r if r == NGX_DECLINED as isize => {
            metrics::inc(&metrics::L402_PAYMENTS_VALID_TOTAL);
            match LAST_PAYMENT_METHOD.with(|m| m.take()) {
                Some(PaymentMethod::Lightning) => {
                    metrics::inc(&metrics::L402_PAYMENTS_LIGHTNING_TOTAL)
                }
                Some(PaymentMethod::Cashu) => {
                    metrics::inc(&metrics::L402_PAYMENTS_CASHU_TOTAL)
                }
                None => {}
            }
        }
        401 => metrics::inc(&metrics::L402_PAYMENTS_INVALID_TOTAL),
        402 => metrics::inc(&metrics::L402_PAYMENTS_MISSING_TOTAL),
        _ => {}
    }

    // Only set L402 header if result is 402
    if result == 402 {
        if let Some((max_requests, window_secs)) = invoice_rate_limit {
            let client_ip = get_client_ip(request);
            if !check_invoice_rate_limit(&client_ip, &request_path, max_requests, window_secs) {
                metrics::inc(&metrics::L402_RATE_LIMITED_TOTAL);
                ngx_log_error!(
                    NGX_LOG_WARN,
                    log_ref,
                    "Invoice rate limit exceeded for IP={} path={}",
                    client_ip,
                    request_path
                );
                // SAFETY: `request` is non-null and valid for this handler's
                // lifetime, as guaranteed by nginx before invoking the handler.
                unsafe {
                    let req = Request::from_ngx_http_request(request);
                    req.add_header_out("Retry-After", &window_secs.to_string());
                }
                return 429;
            }
        }
        // Only count as "issued" once we're past the rate-limit gate.
        metrics::inc(&metrics::L402_CHALLENGES_ISSUED_TOTAL);

        let rt = get_handler_runtime();

        // Check if Cashu is enabled and P2PK mode is active
        // Use initialized state instead of reading env vars (workers don't have access to env)
        let cashu_ecash_support = cashu::is_cashu_ecash_enabled();
        let p2pk_mode = cashu::is_p2pk_mode_enabled();

        ngx_log_error!(
            NGX_LOG_INFO,
            log_ref,
            "cashu_ecash_support={} p2pk_mode={}",
            cashu_ecash_support,
            p2pk_mode
        );

        // If P2PK mode is enabled, send X-Cashu header (NUT-24)
        if cashu_ecash_support && p2pk_mode {
            ngx_log_error!(
                NGX_LOG_INFO,
                log_ref,
                "P2PK mode enabled - generating X-Cashu header (NUT-24)"
            );

            if let Some(cashu_payment_request) = module.get_cashu_payment_request(final_amount) {
                unsafe {
                    let req = Request::from_ngx_http_request(request);
                    req.add_header_out("X-Cashu", &cashu_payment_request);
                    ngx_log_error!(
                        NGX_LOG_INFO,
                        log_ref,
                        "✅ Set X-Cashu header: {}",
                        &cashu_payment_request[..50.min(cashu_payment_request.len())]
                    );
                }
            } else {
                ngx_log_error!(
                    NGX_LOG_ERR,
                    log_ref,
                    "❌ Failed to generate X-Cashu payment request"
                );
            }
        } else {
            ngx_log_error!(
                NGX_LOG_INFO,
                log_ref,
                "X-Cashu header not sent (cashu={} p2pk={})",
                cashu_ecash_support,
                p2pk_mode
            );
        }

        // Always send L402 header as well (for Lightning payments)
        // Pass lnurl_addr for per-location LNURL-based invoice generation
        let invoice_start = Instant::now();
        // Caveats were consumed by the access handler above; rebuild on the 402
        // path only — saves a Vec<String> clone on the auth-pass hot path.
        let challenge_caveats = vec![
            format!("RequestPath = {}", request_path),
            format!("RequestMethod = {}", request_method),
        ];
        let header_result = rt.block_on(async {
            module
                .get_l402_header(
                    challenge_caveats,
                    final_amount,
                    macaroon_timeout,
                    final_lnurl_addr.clone(),
                )
                .await
        });

        if perf_log_enabled() {
            debug!(
                "perf: stage=invoice_generation duration_us={} path={}",
                invoice_start.elapsed().as_micros(),
                request_path
            );
        }

        match header_result {
            Some(header_value) => {
                metrics::inc(&metrics::L402_INVOICES_GENERATED_TOTAL);

                // Set WWW-Authenticate header for API clients
                unsafe {
                    ngx_log_error!(
                        NGX_LOG_INFO,
                        log_ref,
                        "Setting L402/WWW-Authenticate header"
                    );
                    let req = Request::from_ngx_http_request(request);
                    req.add_header_out("WWW-Authenticate", &header_value);
                }

                // Render and send the HTML payment page for browser clients.
                // API clients that check WWW-Authenticate will still function
                // correctly because the header is already set above.
                if let Some((macaroon_b64, invoice)) = parse_l402_header_value(&header_value) {
                    // Show the Cashu tab whenever cashu ecash support is enabled.
                    // P2PK mode controls only the X-Cashu payment request header.
                    let cashu_en = cashu_ecash_support;
                    // Retrieve the Cashu payment request that was generated
                    // earlier (if any) — re-use module ref already in scope.
                    let cashu_pr_owned: Option<String> = if cashu_en {
                        module.get_cashu_payment_request(final_amount)
                    } else {
                        None
                    };
                    let html = payment_page::render_payment_page(
                        &invoice,
                        final_amount,
                        &macaroon_b64,
                        auto_detect_payment,
                        cashu_en,
                        cashu_pr_owned.as_deref(),
                    );
                    return unsafe { send_html_response(request, 402, html) };
                }
                // Fallback: could not parse header, return plain 402
            }
            None => {
                metrics::inc(&metrics::L402_INVOICES_GENERATION_ERRORS_TOTAL);
                ngx_log_error!(NGX_LOG_ERR, log_ref, "Failed to get L402 header");
                return 500;
            }
        }
    }

    if perf_log_enabled() {
        debug!(
            "perf: stage=total duration_us={} path={} result={}",
            handler_start.elapsed().as_micros(),
            request_path,
            result
        );
    }

    result
}

pub fn l402_access_handler(
    auth_header: Option<String>,
    uri: String,
    method: u32,
    amount_msat: i64,
    caveats: Vec<String>,
    lnurl_addr: Option<String>,
    auto_detect_payment: bool,
) -> isize {
    // Reset so the wrapper never reads a stale method from a prior request.
    LAST_PAYMENT_METHOD.with(|m| m.set(None));

    let module = match MODULE.get() {
        Some(m) => m,
        None => {
            error!("Module not initialized — returning 500");
            return 500;
        }
    };

    debug!(
        "🔍 Processing request - Method: {:?}, URI: {:?}",
        method, uri
    );

    if let Some(auth_str) = auth_header {
        // NOTE: never log the raw Authorization header — it contains the
        // macaroon and the one-time-use preimage, which are replayable
        // payment credentials. Log only that a header was present.
        debug!("🔑 Found authorization header (len={})", auth_str.len());

        if auth_str.starts_with("Cashu ") {
            let token = auth_str.trim_start_matches("Cashu ").trim().to_string();

            let rt = get_handler_runtime();

            let verify_result = rt.block_on(async {
                module
                    .verify_cashu_token(&token, amount_msat, lnurl_addr.clone())
                    .await
            });

            match verify_result {
                Ok(true) => {
                    LAST_PAYMENT_METHOD.with(|m| m.set(Some(PaymentMethod::Cashu)));
                    return NGX_DECLINED as isize;
                }
                Ok(false) => {
                    info!("⚠️ Cashu token verification failed");
                    return 401;
                }
                Err(e) => {
                    error!("❌ Error verifying Cashu token: {:?}", e);
                    return 401;
                }
            }
        } else {
            // ── Determine whether the header has a preimage suffix ──────────
            // Classic:     L402 <macaroon>:<hex-preimage>
            // Auto-detect: L402 <macaroon>           (no colon / preimage)
            let token = auth_str.trim().trim_start_matches("L402 ");
            let has_preimage = token.contains(':');

            // ── Try the auto-detect path first when enabled ─────────────────
            if auto_detect_payment && !has_preimage {
                info!("🔍 Auto-detect path: no preimage in header, querying node");

                // 1. Extract payment_hash from macaroon identifier
                let payment_hash = match extract_payment_hash_from_auth_str(&auth_str) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("⚠️ Failed to extract payment_hash from macaroon: {}", e);
                        return 401;
                    }
                };

                // 2. Deserialise macaroon for verification later
                let mac = match utils::get_macaroon_from_string(token.to_string()) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!("⚠️ Failed to deserialise macaroon: {}", e);
                        return 401;
                    }
                };

                // 3. Resolve preimage: Redis cache → node lookup
                let preimage_bytes: Vec<u8> =
                    if let Some(cached) = get_cached_settled_preimage(&payment_hash) {
                        debug!("💾 Using cached settled preimage");
                        cached
                    } else {
                        // Use a lazily initialized static runtime
                        static AUTODETECT_RUNTIME: OnceLock<Runtime> = OnceLock::new();
                        let rt = AUTODETECT_RUNTIME.get_or_init(|| {
                            match tokio::runtime::Builder::new_multi_thread()
                                .enable_all()
                                .build()
                            {
                                Ok(rt) => rt,
                                Err(e) => {
                                    eprintln!("FATAL: failed to create autodetect runtime: {}", e);
                                    std::process::abort();
                                }
                            }
                        });

                        match payment_detector::PAYMENT_DETECTOR.get() {
                            Some(detector) => {
                                const AUTODETECT_LOOKUP_TIMEOUT: Duration =
                                    Duration::from_secs(5);
                                match rt.block_on(async {
                                    tokio::time::timeout(
                                        AUTODETECT_LOOKUP_TIMEOUT,
                                        detector.lookup_settled_invoice(&payment_hash),
                                    )
                                    .await
                                }) {
                                    Ok(Ok(Some(p))) => {
                                        // Cache for future requests
                                        if let Err(e) = cache_settled_preimage(&payment_hash, &p) {
                                            warn!("⚠️ Failed to cache settled preimage: {}", e);
                                        }
                                        p
                                    }
                                    Ok(Ok(None)) => {
                                        info!("⏳ Invoice not yet settled — returning 402");
                                        return 402;
                                    }
                                    Ok(Err(e)) => {
                                        error!("❌ Node invoice lookup failed: {}", e);
                                        return 500;
                                    }
                                    Err(_) => {
                                        warn!(
                                            "Auto-detect invoice lookup timed out after {}s — returning 402",
                                            AUTODETECT_LOOKUP_TIMEOUT.as_secs()
                                        );
                                        return 402;
                                    }
                                }
                            }
                            None => {
                                error!("❌ PAYMENT_DETECTOR not initialised");
                                return 500;
                            }
                        }
                    };

                // 4. Check replay
                if is_preimage_used(&preimage_bytes) {
                    error!("🚨 Replay attack detected: preimage already used");
                    return 401;
                }

                // 5. Build verifier (same logic as the classic path)
                let mut verifier = Verifier::default();
                verifier.satisfy_general(|predicate| {
                    let predicate_str = match std::str::from_utf8(&predicate.0) {
                        Ok(s) => s,
                        Err(_) => return false,
                    };
                    if let Some(secs_str) = predicate_str.strip_prefix("ExpiresAt = ") {
                        if let Ok(ts) = secs_str.parse::<i64>() {
                            let current_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            return current_time <= ts;
                        }
                    }
                    // `RequestMethod = …` and `RequestPath = …` must be
                    // satisfied by the exact set only. Falling through to
                    // `true` would let a token issued for one route or method
                    // verify against any other, defeating the per-route and
                    // per-method binding on the macaroon (CWE-863).
                    if predicate_str.starts_with("RequestMethod = ")
                        || predicate_str.starts_with("RequestPath = ")
                    {
                        return false;
                    }
                    true
                });
                for caveat in &caveats {
                    if !caveat.starts_with("ExpiresAt = ") {
                        verifier.satisfy_exact(caveat.clone().into());
                    }
                }

                // 6. Verify macaroon signature + payment-hash binding
                if preimage_bytes.len() != 32 {
                    error!("❌ Preimage from node is not 32 bytes");
                    return 500;
                }
                let mut preimage_arr = [0u8; 32];
                preimage_arr.copy_from_slice(&preimage_bytes);
                let preimage = lightning::ln::PaymentPreimage(preimage_arr);

                match l402::verify_l402_with_verifier(
                    &mac,
                    &mut verifier,
                    module.middleware.root_key.clone(),
                    preimage,
                ) {
                    Ok(_) => {
                        info!("✅ L402 auto-detect verification successful");
                        LAST_PAYMENT_METHOD.with(|m| m.set(Some(PaymentMethod::Lightning)));
                        // SET NX EX is the authoritative atomic admission gate.
                        // Ok(false) means another worker already claimed this
                        // preimage — treat as replay and reject.
                        match store_preimage_as_used(&preimage_bytes) {
                            Ok(true) => return NGX_DECLINED as isize,
                            Ok(false) => {
                                warn!("🚨 Preimage already claimed by concurrent worker — replay rejected");
                                return 401;
                            }
                            Err(e) if e.contains("Redis not configured") => {
                                // Redis was never set up — fall back to in-process
                                // cache (single-worker protection only). This is an
                                // explicit operator choice, not an outage.
                                warn!("⚠️ Redis not configured — replay protection is in-process only (single-worker)");
                                return NGX_DECLINED as isize;
                            }
                            Err(e) => {
                                // Redis was configured but is currently unreachable —
                                // fail-closed to prevent replay during outages (CWE-362).
                                error!("❌ Redis unavailable for preimage claim — rejecting to prevent replay: {}", e);
                                return 503;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ L402 auto-detect verification failed: {:?}", e);
                        return 401;
                    }
                }
            }

            // ── Classic path: preimage provided by client ───────────────────
            match utils::parse_l402_header(&auth_str) {
                Ok((mac, preimage)) => {
                    // Fast-fail: known-replayed preimages are rejected before
                    // running macaroon verification. The SET NX EX below is the
                    // authoritative cross-worker admission gate.
                    if is_preimage_used(&preimage.0) {
                        warn!("🚨 Replay attack detected: preimage already used");
                        return 401;
                    }

                    // Check expiry using verifier
                    let mut verifier = Verifier::default();
                    verifier.satisfy_general(|predicate| {
                        let predicate_str = match std::str::from_utf8(&predicate.0) {
                            Ok(s) => s,
                            Err(_) => return false,
                        };
                        if let Some(secs_str) = predicate_str.strip_prefix("ExpiresAt = ") {
                            if let Ok(ts) = secs_str.parse::<i64>() {
                                let current_time = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map(|d| d.as_secs() as i64)
                                    .unwrap_or(0);
                                let is_valid = current_time <= ts;
                                return is_valid;
                            }
                        }
                        // `RequestMethod = …` and `RequestPath = …` must be
                        // satisfied by the exact set only. Falling through to
                        // `true` would let a token issued for one route or
                        // method verify against any other, defeating the
                        // per-route and per-method binding (CWE-863).
                        if predicate_str.starts_with("RequestMethod = ")
                            || predicate_str.starts_with("RequestPath = ")
                        {
                            return false;
                        }
                        true
                    });

                    // Add exact caveats, ignoring ExpiresAt
                    for caveat in caveats {
                        if !caveat.starts_with("ExpiresAt = ") {
                            verifier.satisfy_exact(caveat.into());
                        }
                    }

                    match l402::verify_l402_with_verifier(
                        &mac,
                        &mut verifier,
                        module.middleware.root_key.clone(),
                        preimage,
                    ) {
                        Ok(_) => {
                            info!("✅ L402 verification successful");
                            LAST_PAYMENT_METHOD.with(|m| m.set(Some(PaymentMethod::Lightning)));
                            // SET NX EX is the authoritative atomic admission gate.
                            // Ok(false) means another worker already claimed this
                            // preimage — treat as replay and reject.
                            match store_preimage_as_used(&preimage.0) {
                                Ok(true) => return NGX_DECLINED as isize,
                                Ok(false) => {
                                    warn!("🚨 Preimage already claimed by concurrent worker — replay rejected");
                                    return 401;
                                }
                                Err(e) if e.contains("Redis not configured") => {
                                    // Redis was never set up — fall back to in-process
                                    // cache (single-worker protection only). This is an
                                    // explicit operator choice, not an outage.
                                    warn!("⚠️ Redis not configured — replay protection is in-process only (single-worker)");
                                    return NGX_DECLINED as isize;
                                }
                                Err(e) => {
                                    // Redis was configured but is currently unreachable —
                                    // fail-closed to prevent replay during outages (CWE-362).
                                    error!("❌ Redis unavailable for preimage claim — rejecting to prevent replay: {}", e);
                                    return 503;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("⚠️ L402 verification failed: {:?}", e);
                            return 401;
                        }
                    }
                }
                Err(e) => {
                    warn!("⚠️ Failed to parse L402 header: {:?}", e);
                    return 401;
                }
            }
        }
    }

    debug!("🚨 No authorization header found, sending L402 challenge");
    402
}

pub unsafe extern "C" fn init_module(cycle: *mut ngx_cycle_s) -> isize {
    if cycle.is_null() {
        return -1;
    }

    // SAFETY: `cycle->log` is guaranteed valid by Nginx before invoking
    // module init callbacks; it points to the global error log.
    let log = (*cycle).log;

    // Initialize logger - this is critical for RUST_LOG to work
    let _ = env_logger::try_init();

    info!("🚀 Starting L402 module initialization");
    ngx_log_error!(NGX_LOG_INFO, log, "Starting module initialization");

    payment_detector::init_payment_detector();
    manifest::init_env_snapshot();

    // Cache the LN backend type string for structured log lines. We can't
    // read env vars from worker threads, so snapshot it here.
    let _ = LN_BACKEND_LABEL
        .set(std::env::var("LN_CLIENT_TYPE").unwrap_or_else(|_| "LNURL".to_string()));

    // Check if Cashu eCash support is enabled
    let cashu_ecash_support_var =
        std::env::var("CASHU_ECASH_SUPPORT").unwrap_or_else(|_| "false".to_string());
    let cashu_ecash_support = cashu_ecash_support_var.trim().to_lowercase() == "true";

    if cashu_ecash_support {
        info!("🪙 Cashu eCash support is enabled");

        // Initialize Cashu SQLite database
        let db_url = std::env::var("CASHU_DB_PATH")
            .unwrap_or_else(|_| "/var/lib/nginx/cashu_tokens.db".to_string());
        ngx_log_error!(NGX_LOG_INFO, log, "CASHU_DB_PATH: '{}'", db_url);

        match cashu::initialize_cashu(&db_url) {
            Ok(_) => {
                ngx_log_error!(NGX_LOG_INFO, log, "Cashu database initialized successfully");
            }
            Err(e) => {
                ngx_log_error!(NGX_LOG_ERR, log, "Failed to initialize Cashu: {}", e);
            }
        }

        // Initialize whitelisted mints if configured
        if let Ok(whitelisted_mints) = std::env::var("CASHU_WHITELISTED_MINTS") {
            ngx_log_error!(
                NGX_LOG_INFO,
                log,
                "CASHU_WHITELISTED_MINTS: '{}'",
                whitelisted_mints
            );
            match cashu::initialize_whitelisted_mints(&whitelisted_mints) {
                Ok(_) => {
                    ngx_log_error!(
                        NGX_LOG_INFO,
                        log,
                        "Whitelisted mints initialized successfully"
                    );
                }
                Err(e) => {
                    ngx_log_error!(
                        NGX_LOG_ERR,
                        log,
                        "Failed to initialize whitelisted mints: {}",
                        e
                    );
                }
            }
        } else {
            info!("ℹ️ No whitelisted mints configured - all mints will be accepted");
        }

        // Initialize P2PK mode if enabled
        match cashu::initialize_p2pk_mode() {
            Ok(_) => {
                ngx_log_error!(NGX_LOG_INFO, log, "P2PK mode initialization completed");
            }
            Err(e) => {
                ngx_log_error!(NGX_LOG_ERR, log, "Failed to initialize P2PK mode: {}", e);
            }
        }
    } else {
        info!("ℹ️ Cashu eCash support is disabled");
    }

    MODULE.get_or_init(|| {
        info!("🔄 Initializing runtime and L402Module");
        openssl_probe::init_openssl_env_vars();
        let rt = Runtime::new().expect("Failed to create runtime");
        let module = rt.block_on(async {
            let m = L402Module::new().await;
            if cashu_ecash_support {
                cashu::restore_wallets_state().await;
            }
            m
        });

        // Initialize LN client for cashu redemption
        let ln_client = module.middleware.ln_client.clone();
        let ln_client_type =
            std::env::var("LN_CLIENT_TYPE").unwrap_or_else(|_| "LNURL".to_string());
        if let Err(e) = cashu::initialize_ln_client(ln_client, ln_client_type) {
            error!("⚠️ Failed to initialize LN client for cashu: {}", e);
        }

        info!("✅ L402Module initialized successfully");
        module
    });

    info!("✅ L402 module initialization complete");

    let redeem_on_lightning = std::env::var("CASHU_REDEEM_ON_LIGHTNING")
        .unwrap_or_else(|_| "false".to_string())
        .trim()
        .to_lowercase()
        == "true";

    if redeem_on_lightning && cashu_ecash_support {
        ngx_log_error!(NGX_LOG_INFO, log, "Automatic Cashu redemption enabled");

        // Get redemption interval
        let interval_secs = std::env::var("CASHU_REDEMPTION_INTERVAL_SECS")
            .unwrap_or_else(|_| "3600".to_string()) // Default 1 hour
            .parse::<u64>()
            .unwrap_or(3600);

        let Some(_module) = MODULE.get() else {
            error!("Module not initialized — skipping Cashu redemption");
            return 0;
        };

        // Spawn redemption task in a separate thread to avoid blocking nginx
        let _ = std::thread::Builder::new()
            .name("cashu_redemption".into())
            .spawn(move || {
                info!("🔄 Starting Cashu redemption task");

                // Create a new runtime for this thread
                let thread_rt = Runtime::new().expect("Failed to create thread runtime");

                cashu_redemption_logger::log_redemption("🔄 Cashu redemption task started");

                let mut iteration = 0;
                loop {
                    cashu_redemption_logger::log_redemption(&format!(
                        "DEBUG: Loop iteration starting, iteration was {}",
                        iteration
                    ));
                    iteration += 1;
                    let msg = format!("🔄 Iteration #{} starting", iteration);
                    cashu_redemption_logger::log_redemption(&msg);
                    info!("🔄 Cashu redemption iteration #{} starting...", iteration);

                    // Run async redemption in the tokio runtime
                    let result = thread_rt.block_on(async { cashu::redeem_to_lightning().await });

                    match result {
                        Ok(true) => {
                            cashu_redemption_logger::log_redemption(
                                "✅ Successfully redeemed Cashu tokens",
                            );
                            info!("✅ Successfully redeemed Cashu tokens");
                        }
                        Ok(false) => {
                            cashu_redemption_logger::log_redemption("ℹ️ No Cashu tokens to redeem");
                            info!("ℹ️ No Cashu tokens to redeem");
                        }
                        Err(e) => {
                            let msg = format!("❌ Error redeeming Cashu tokens: {}", e);
                            cashu_redemption_logger::log_redemption(&msg);
                            error!("❌ Error redeeming Cashu tokens: {}", e);
                        }
                    }

                    let msg = format!("😴 Sleeping for {} seconds", interval_secs);
                    cashu_redemption_logger::log_redemption(&msg);
                    info!(
                        "😴 Cashu redemption task sleeping for {} seconds",
                        interval_secs
                    );

                    // Use std::thread::sleep instead of tokio::time::sleep
                    cashu_redemption_logger::log_redemption("💤 About to sleep...");
                    let sleep_result = std::panic::catch_unwind(|| {
                        std::thread::sleep(std::time::Duration::from_secs(interval_secs));
                    });
                    cashu_redemption_logger::log_redemption("💤 Sleep completed");

                    if sleep_result.is_err() {
                        cashu_redemption_logger::log_redemption("❌ Sleep panicked!");
                        error!("❌ Sleep panicked!");
                        continue;
                    }

                    cashu_redemption_logger::log_redemption(
                        "⏰ Woke up from sleep, starting next iteration",
                    );
                    info!("⏰ Woke up from sleep");
                }
            });
    }
    0
}

/// Handle dry-run (shadow) mode: evaluate everything, log + increment metrics,
/// but never block the request. Always returns [`NGX_DECLINED`] so nginx
/// continues to the next phase and the upstream response is served as 200.
///
/// A synthesised L402 challenge is attached via the `WWW-Authenticate` *and*
/// `X-L402-Dry-Run-Challenge` response headers so operators can inspect the
/// challenge that *would* have been issued without parsing logs. Failure to
/// generate the challenge (e.g. LN backend unreachable) is counted but does
/// not fail the request.
#[allow(clippy::too_many_arguments)]
fn handle_dry_run_passthrough(
    request: *mut ngx_http_request_t,
    log_ref: *mut ngx_log_s,
    module: &L402Module,
    request_path: &str,
    final_amount: i64,
    price_source: &'static str,
    final_lnurl_addr: Option<String>,
    macaroon_timeout: i64,
    caveats: Vec<String>,
    result: isize,
    auth_present: bool,
    invoice_rate_limit: Option<(u32, u64)>,
) -> isize {
    metrics::inc(&metrics::L402_DRY_RUN_REQUESTS_TOTAL);
    if final_amount > 0 {
        metrics::add(&metrics::L402_DRY_RUN_PRICE_MSAT_SUM, final_amount as u64);
    }

    let would_return: u16 = match result {
        r if r == NGX_DECLINED as isize => 200,
        401 => 401,
        402 => 402,
        other if (100..600).contains(&other) => other as u16,
        _ => 0,
    };

    // Check the invoice rate limiter when an invoice *would* be issued.
    // Without this, dry-run mode can hit the LN backend harder than enforce
    // mode — the opposite of what "safe rollout" should mean.
    let client_ip = get_client_ip(request);
    let rate_limited = if would_return == 402 {
        match invoice_rate_limit {
            Some((max_requests, window_secs)) => {
                !check_invoice_rate_limit(&client_ip, request_path, max_requests, window_secs)
            }
            None => false,
        }
    } else {
        false
    };

    match would_return {
        200 => metrics::inc(&metrics::L402_DRY_RUN_WOULD_ALLOW_TOTAL),
        401 | 402 => metrics::inc(&metrics::L402_DRY_RUN_WOULD_BLOCK_TOTAL),
        _ => {}
    }
    if rate_limited {
        metrics::inc(&metrics::L402_DRY_RUN_RATE_LIMITED_TOTAL);
    }

    let auth_state = match (auth_present, result) {
        (false, _) => "missing",
        (true, r) if r == NGX_DECLINED as isize => "valid",
        (true, _) => "invalid",
    };

    let backend = LN_BACKEND_LABEL
        .get()
        .map(String::as_str)
        .unwrap_or("unknown");

    // Structured JSON line — easy to pick out of nginx error_log with jq/grep
    // and forward to Loki / Splunk / Datadog.
    info!(
        "{{\"event\":\"l402_dry_run\",\"route\":\"{route}\",\"price_msat\":{price},\"price_source\":\"{src}\",\"backend\":\"{backend}\",\"client_ip\":\"{ip}\",\"auth_state\":\"{state}\",\"would_return\":{status},\"rate_limited\":{rl}}}",
        route = escape_json(request_path),
        price = final_amount,
        src = price_source,
        backend = backend,
        ip = escape_json(&client_ip),
        state = auth_state,
        status = would_return,
        rl = rate_limited,
    );

    // SAFETY: `request` is non-null and valid for this handler's lifetime,
    // as guaranteed by nginx before invoking the access handler.
    let req = unsafe { Request::from_ngx_http_request(request) };
    req.add_header_out("X-L402-Dry-Run", "1");

    if would_return == 402 && !rate_limited {
        req.add_header_out("X-L402-Dry-Run-Price-Msat", &final_amount.to_string());

        // Hard cap on the LN backend round-trip. Shadow mode must not add
        // latency to upstream traffic: if the backend stalls we bail out,
        // count a challenge error, and pass the request through without a
        // challenge header.
        const DRY_RUN_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(5);

        let rt = dry_run_runtime();
        let header_result = rt.block_on(async {
            tokio::time::timeout(
                DRY_RUN_CHALLENGE_TIMEOUT,
                module.get_l402_header(
                    caveats,
                    final_amount,
                    macaroon_timeout,
                    final_lnurl_addr,
                ),
            )
            .await
        });

        match header_result {
            Ok(Some(header_value)) => {
                req.add_header_out("WWW-Authenticate", &header_value);
                req.add_header_out("X-L402-Dry-Run-Challenge", &header_value);
            }
            Ok(None) => {
                metrics::inc(&metrics::L402_DRY_RUN_CHALLENGE_ERRORS_TOTAL);
                ngx_log_error!(
                    NGX_LOG_WARN,
                    log_ref,
                    "[l402_dry_run] failed to synthesise challenge for {}",
                    request_path
                );
            }
            Err(_) => {
                metrics::inc(&metrics::L402_DRY_RUN_CHALLENGE_ERRORS_TOTAL);
                ngx_log_error!(
                    NGX_LOG_WARN,
                    log_ref,
                    "[l402_dry_run] challenge synthesis timed out after {}s for {}",
                    DRY_RUN_CHALLENGE_TIMEOUT.as_secs(),
                    request_path
                );
            }
        }
    } else if would_return == 402 && rate_limited {
        // Rate-limited: surface the signal without hitting the LN backend.
        req.add_header_out("X-L402-Dry-Run-Price-Msat", &final_amount.to_string());
        req.add_header_out("X-L402-Dry-Run-Rate-Limited", "1");
        if let Some((_, window_secs)) = invoice_rate_limit {
            req.add_header_out("X-L402-Dry-Run-Retry-After", &window_secs.to_string());
        }
        ngx_log_error!(
            NGX_LOG_WARN,
            log_ref,
            "[l402_dry_run] invoice rate limit exceeded for IP={} path={}",
            client_ip,
            request_path
        );
    }
    // `would_return` 200/401 fall through with just `X-L402-Dry-Run: 1`:
    // no price leak on paid-valid, no challenge replay on bad token.

    NGX_DECLINED as isize
}

fn dry_run_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("FATAL: failed to create tokio runtime: {}", e);
                std::process::abort();
            }
        }
    })
}

/// Minimal JSON-string escaper. Handles the bytes mandated by RFC 8259.
/// Good enough for a single log line; avoids pulling in a JSON crate on
/// the hot path.
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Content-phase handler for `l402_metrics`. Serves the Prometheus text
/// exposition format at the configured location (e.g. `/metrics`).
///
/// Only `GET` and `HEAD` are accepted; anything else returns `405`.
pub unsafe extern "C" fn l402_metrics_content_handler(r: *mut ngx_http_request_t) -> ngx_int_t {
    // SAFETY: nginx passes a non-null, valid request pointer to content
    // phase handlers for the lifetime of the call.
    let r_ref = unsafe { &mut *r };

    let method = r_ref.method as u32;
    if method & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_HTTP_NOT_ALLOWED as ngx_int_t;
    }

    let rc = unsafe { ngx_http_discard_request_body(r) };
    if rc != NGX_OK as ngx_int_t {
        return rc;
    }

    let body = metrics::render();
    let body_len = body.len();

    // SAFETY: `r` is valid; `Request::from_ngx_http_request` just wraps the
    // pointer, `pool()` returns a Pool tied to the request lifetime.
    let req = unsafe { Request::from_ngx_http_request(r) };
    let pool = req.pool();

    let Some(mut buf) = pool.create_buffer_from_str(&body) else {
        return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
    };
    buf.set_last_buf(true);
    buf.set_last_in_chain(true);

    let chain = pool.alloc_type::<ngx_chain_t>();
    if chain.is_null() {
        return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
    }
    // SAFETY: `chain` was allocated above from the request pool.
    unsafe {
        (*chain).buf = buf.as_ngx_buf_mut();
        (*chain).next = std::ptr::null_mut();
    }

    req.set_status(HTTPStatus::OK);
    req.set_content_length_n(body_len);
    let _ = req.add_header_out("Content-Type", "text/plain; version=0.0.4; charset=utf-8");

    let status = req.send_header();
    if status.0 == NGX_ERROR as ngx_int_t || status.0 > NGX_OK as ngx_int_t || req.header_only() {
        return status.0;
    }

    // SAFETY: `chain` is non-null, was just initialised, and lives for the
    // request via the request pool.
    unsafe { req.output_filter(&mut *chain).0 }
}

pub unsafe extern "C" fn ngx_http_l402_dry_run_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf`, `conf`, and `(*cf).args` are guaranteed valid by Nginx
    // during config-parsing callbacks. `args.add(1)` is safe because
    // NGX_CONF_TAKE1 ensures exactly one argument is present.
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let val = (*args.add(1)).to_str().unwrap_or_default();

        if val.eq_ignore_ascii_case("on") {
            conf.dry_run = Some(true);
            info!("⚙️ l402_dry_run enabled (shadow mode — requests will pass through)");
        } else if val.eq_ignore_ascii_case("off") {
            conf.dry_run = Some(false);
        } else {
            error!("Invalid l402_dry_run value: '{}' (expected on/off)", val);
            return b"l402_dry_run: expected 'on' or 'off'\0".as_ptr() as *mut c_char;
        }
    }
    std::ptr::null_mut()
}

pub unsafe extern "C" fn ngx_http_l402_metrics_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf` is guaranteed valid by Nginx during config parsing.
    // `ngx_http_conf_get_module_loc_conf` requires a valid module reference.
    // `ngx_http_core_module` is a static global defined by nginx core.
    unsafe {
        let clcf: *mut ngx::ffi::ngx_http_core_loc_conf_t = NgxHttpCoreModule::location_conf_mut(&*cf)
            .map(|r| r as *mut _)
            .unwrap_or(std::ptr::null_mut());
        if clcf.is_null() {
            return b"l402_metrics: missing core loc conf\0".as_ptr() as *mut c_char;
        }
        // Refuse to silently clobber a content handler registered by another
        // directive (e.g. `proxy_pass`, `return`, `alias` + `try_files`, etc.).
        // Fail fast at `nginx -t` rather than surprise operators at runtime.
        if (*clcf).handler.is_some() {
            error!("l402_metrics: another content handler is already registered for this location");
            return b"l402_metrics: conflicts with another content handler in this location\0"
                .as_ptr() as *mut c_char;
        }
        (*clcf).handler = Some(l402_metrics_content_handler);
    }
    info!("⚙️ l402_metrics endpoint registered");
    std::ptr::null_mut()
}

pub unsafe extern "C" fn ngx_http_l402_manifest_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    _conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: same guarantees as `ngx_http_l402_metrics_set` above.
    unsafe {
        let clcf: *mut ngx::ffi::ngx_http_core_loc_conf_t = NgxHttpCoreModule::location_conf_mut(&*cf)
            .map(|r| r as *mut _)
            .unwrap_or(std::ptr::null_mut());
        if clcf.is_null() {
            return b"l402_manifest: missing core loc conf\0".as_ptr() as *mut c_char;
        }
        if (*clcf).handler.is_some() {
            error!(
                "l402_manifest: another content handler is already registered for this location"
            );
            return b"l402_manifest: conflicts with another content handler in this location\0"
                .as_ptr() as *mut c_char;
        }
        (*clcf).handler = Some(l402_manifest_content_handler);
    }
    info!("⚙️ l402_manifest endpoint registered (.well-known/l402-services capability manifest)");
    std::ptr::null_mut()
}

pub unsafe extern "C" fn ngx_http_l402_manifest_hide_set(
    _cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `conf` points to this location's ModuleConfig, guaranteed
    // valid by nginx during directive parsing.
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        conf.manifest_hidden = true;
    }
    info!("⚙️ l402_manifest_hide: excluding this route from /.well-known/l402-services");
    std::ptr::null_mut()
}

/// Content-phase handler for `l402_manifest`. Serves the
/// `.well-known/l402-services` capability manifest as JSON.
///
/// Only `GET` and `HEAD` are accepted; anything else returns `405`. The
/// manifest is rebuilt on every request — cheap because the registry is
/// in-process and small (one entry per l402-protected location).
pub unsafe extern "C" fn l402_manifest_content_handler(r: *mut ngx_http_request_t) -> ngx_int_t {
    let r_ref = unsafe { &mut *r };

    let method = r_ref.method as u32;
    if method & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_HTTP_NOT_ALLOWED as ngx_int_t;
    }

    let rc = unsafe { ngx_http_discard_request_body(r) };
    if rc != NGX_OK as ngx_int_t {
        return rc;
    }

    let snapshots = collect_route_snapshots();
    let body = manifest::render(&snapshots);
    let body_len = body.len();

    let req = unsafe { Request::from_ngx_http_request(r) };
    let pool = req.pool();

    let Some(mut buf) = pool.create_buffer_from_str(&body) else {
        return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
    };
    buf.set_last_buf(true);
    buf.set_last_in_chain(true);

    let chain = pool.alloc_type::<ngx_chain_t>();
    if chain.is_null() {
        return NGX_HTTP_INTERNAL_SERVER_ERROR as ngx_int_t;
    }
    // SAFETY: `chain` was just allocated from the request pool.
    unsafe {
        (*chain).buf = buf.as_ngx_buf_mut();
        (*chain).next = std::ptr::null_mut();
    }

    req.set_status(HTTPStatus::OK);
    req.set_content_length_n(body_len);
    let _ = req.add_header_out("Content-Type", "application/json; charset=utf-8");

    let status = req.send_header();
    if status.0 == NGX_ERROR as ngx_int_t || status.0 > NGX_OK as ngx_int_t || req.header_only() {
        return status.0;
    }

    // SAFETY: `chain` is non-null, initialised, and lives for the request
    // via the request pool.
    unsafe { req.output_filter(&mut *chain).0 }
}

/// Read each registered route's `ModuleConfig` and build a snapshot. Called
/// at request time so post-merge values (amount_msat, rate_limit, …) are
/// reflected.
fn collect_route_snapshots() -> Vec<manifest::RouteSnapshot> {
    let Ok(registry) = manifest_registry().lock() else {
        return Vec::new();
    };
    registry
        .iter()
        .filter_map(|entry| {
            if entry.conf.0.is_null() {
                return None;
            }
            // SAFETY: the pointer was captured during config parse; the
            // pointee lives in nginx's cycle pool for the lifetime of the
            // worker process. No mutable aliasing — we hold a shared ref.
            let conf = unsafe { &*entry.conf.0 };
            if !conf.enable {
                // `l402 off;` in a child location overrides a parent `on`.
                return None;
            }
            Some(manifest::RouteSnapshot {
                path: entry.path.clone(),
                price_msat: conf.amount_msat,
                macaroon_timeout: conf.macaroon_timeout,
                lnurl_addr: conf.lnurl_addr.clone(),
                rate_limit: conf.invoice_rate_limit,
                auto_detect_payment: conf.auto_detect_payment,
                hidden: conf.manifest_hidden,
            })
        })
        .collect()
}

pub unsafe extern "C" fn ngx_http_l402_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf`, `conf`, and `(*cf).args` are guaranteed valid by Nginx
    // during config-parsing callbacks. `args.add(1)` is safe because
    // NGX_CONF_TAKE1 ensures exactly one argument is present.
    unsafe {
        let conf_ptr = conf as *mut ModuleConfig;
        let conf = &mut *conf_ptr;
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val = (*args.add(1)).to_str().unwrap_or_default().trim().to_lowercase();

        match val.as_str() {
            "on" | "true" | "1" | "yes" => {
                conf.enable = true;
                info!("⚙️ Enabled L402 for this location");
                // Snapshot the location's path now and remember the conf
                // pointer; the `.well-known/l402-services` handler re-reads the conf
                // at request time so post-merge values (amount_msat, etc.)
                // are picked up correctly.
                if let Some(path) = location_name_str(cf) {
                    if let Ok(mut reg) = manifest_registry().lock() {
                        // Skip dup entries — `l402 on;` could appear more
                        // than once in pathological configs.
                        if !reg
                            .iter()
                            .any(|r| r.path == path && r.conf.0 == conf_ptr)
                        {
                            reg.push(RouteRegistration {
                                path,
                                conf: ConfPtr(conf_ptr),
                            });
                        }
                    }
                }
            }
            "off" | "false" | "0" | "no" => {
                conf.enable = false;
                info!("⚙️ Disabled L402 for this location");
            }
            _ => {
                error!("❌ Invalid l402 configuration value: {}", val);
            }
        }
    };

    std::ptr::null_mut()
}

/// Read the current location's name (path) from the core loc conf during
/// directive parsing. Returns `None` if nginx hasn't populated `name` yet
/// (e.g. directive used outside a `location` block).
unsafe fn location_name_str(cf: *mut ngx_conf_t) -> Option<String> {
    let clcf: *mut ngx::ffi::ngx_http_core_loc_conf_t = NgxHttpCoreModule::location_conf_mut(&*cf)
        .map(|r| r as *mut _)
        .unwrap_or(std::ptr::null_mut());
    if clcf.is_null() {
        return None;
    }
    let name: ngx_str_t = (*clcf).name;
    if name.len == 0 || name.data.is_null() {
        return None;
    }
    let slice = std::slice::from_raw_parts(name.data, name.len);
    Some(String::from_utf8_lossy(slice).into_owned())
}

pub unsafe extern "C" fn ngx_http_l402_amount_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf`, `conf`, and `(*cf).args` are guaranteed valid by Nginx
    // during config-parsing callbacks. `args.add(1)` is safe because
    // NGX_CONF_TAKE1 ensures exactly one argument is present.
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val = (*args.add(1)).to_str().unwrap_or_default();

        match val.parse::<i64>() {
            Ok(amount) if amount > 0 => {
                conf.amount_msat = amount;
                info!("⚙️ Set L402 amount_msat to {}", amount);
            }
            _ => {
                error!("❌ Invalid amount_msat configuration value: {}", val);
                return std::ptr::null_mut();
            }
        }
    };

    std::ptr::null_mut()
}

pub unsafe extern "C" fn ngx_http_l402_timeout_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf`, `conf`, and `(*cf).args` are guaranteed valid by Nginx
    // during config-parsing callbacks. `args.add(1)` is safe because
    // NGX_CONF_TAKE1 ensures exactly one argument is present.
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val = (*args.add(1)).to_str().unwrap_or_default();

        match val.parse::<i64>() {
            Ok(timeout) if timeout >= 0 => {
                // Allow 0 (no timeout)
                conf.macaroon_timeout = timeout;
                if timeout == 0 {
                    info!("⚙️ Set L402 macaroon timeout to never expire (0)");
                } else {
                    info!("⚙️ Set L402 macaroon timeout to {} seconds", timeout);
                }
            }
            _ => {
                error!("❌ Invalid macaroon_timeout configuration value: {}", val);
                return std::ptr::null_mut();
            }
        }
    };

    std::ptr::null_mut()
}

pub unsafe extern "C" fn ngx_http_l402_lnurl_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf`, `conf`, and `(*cf).args` are guaranteed valid by Nginx
    // during config-parsing callbacks. `args.add(1)` is safe because
    // NGX_CONF_TAKE1 ensures exactly one argument is present.
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val_raw = (*args.add(1)).to_str().unwrap_or_default();
        let val = val_raw.trim();

        let lnurl_addr = if !val.is_empty() {
            val.to_string()
        } else {
            match std::env::var("LNURL_ADDRESS") {
                Ok(env_val) if !env_val.is_empty() => env_val,
                _ => {
                    error!("❌ LNURL_ADDRESS environment variable is not set and no value provided in config");
                    return b"LNURL_ADDRESS environment variable is not set\0".as_ptr() as *mut c_char;
                }
            }
        };

        conf.lnurl_addr = Some(lnurl_addr.clone());
        info!("Set L402 LNURL address to: {}", lnurl_addr);
    }

    std::ptr::null_mut()
}

// accepted: "5r/m", "10r/h", "2r/s", or bare "5" (defaults to per minute)
fn parse_rate_limit(val: &str) -> Option<(u32, u64)> {
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

/// Returns the client IP, preferring X-Real-IP then the first entry of
/// X-Forwarded-For over the direct socket address. Falls back to `"unknown"`.
///
/// Note: X-Forwarded-For can be spoofed by clients unless nginx is configured
/// to strip or overwrite it via the realip module before reaching this handler.
fn get_client_ip(request: *mut ngx_http_request_t) -> String {
    // SAFETY: called only from `l402_access_handler_wrapper`, where `request`
    // is the pointer nginx passed to the access handler and is guaranteed
    // non-null and valid for the handler's lifetime.
    unsafe {
        if request.is_null() {
            return "unknown".to_string();
        }
        let r = &*request;

        // X-Real-IP: single IP set by a trusted reverse proxy
        if !r.headers_in.x_real_ip.is_null() {
            let val = (*r.headers_in.x_real_ip).value.to_str().unwrap_or_default().trim().to_string();
            if !val.is_empty() {
                return val;
            }
        }

        // X-Forwarded-For: "client, proxy1, proxy2" — leftmost is the origin
        if !r.headers_in.x_forwarded_for.is_null() {
            let val_str = (*r.headers_in.x_forwarded_for).value.to_str().unwrap_or_default();
            if let Some(ip) = val_str.split(',').next() {
                let ip = ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }

        // Direct socket address — unreliable behind a load balancer
        let conn = r.connection;
        if conn.is_null() {
            return "unknown".to_string();
        }
        (*conn).addr_text.to_str().unwrap_or_default().to_string()
    }
}

/// Fixed-window INCR+EXPIRE counter. Fails open if Redis is unavailable.
fn check_invoice_rate_limit(ip: &str, path: &str, max_requests: u32, window_secs: u64) -> bool {
    let Some(pool) = REDIS_POOL.get() else {
        warn!("Redis not configured - invoice rate limiting disabled");
        return true;
    };

    let Ok(mut conn) = pool.get() else {
        error!("Failed to get Redis connection for invoice rate limit check");
        return true;
    };

    // Hash the request path so the Redis key has a bounded length and an
    // attacker cannot exhaust Redis memory or cause key collisions by sending
    // arbitrarily long / crafted paths. Mirrors preimage_redis_key().
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let path_hash = hex::encode(hasher.finalize());
    let key = format!("l402:invoice_rate:{}:{}", ip, &path_hash[..16]);

    let count: u64 = match redis::Script::new(
        r#"
        local current = redis.call("INCR", KEYS[1])
        if current == 1 then
            redis.call("EXPIRE", KEYS[1], ARGV[1])
        end
        return current
        "#,
    )
    .key(&key)
    .arg(window_secs)
    .invoke(&mut conn)
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to update invoice rate limit counter: {}", e);
            return true;
        }
    };

    let allowed = count <= max_requests as u64;
    if !allowed {
        warn!(
            "Invoice rate limit exceeded for IP={} path={} ({}/{})",
            ip, path, count, max_requests
        );
    }
    allowed
}

/// nginx directive handler for `l402_invoice_rate_limit`.
///
/// Accepted syntax (mirrors nginx's own `limit_req_zone` style):
///   `l402_invoice_rate_limit 5r/m;`   - 5 invoices per minute per IP per route
///   `l402_invoice_rate_limit 10r/h;`  - 10 per hour
///   `l402_invoice_rate_limit 2r/s;`   - 2 per second
///   `l402_invoice_rate_limit 5;`      - 5 per minute (shorthand)
pub unsafe extern "C" fn ngx_http_l402_invoice_rate_limit_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    // SAFETY: `cf` and `conf` are non-null and valid for the duration of the
    // configuration phase. `conf` points to a `ModuleConfig` allocated by
    // `create_loc_conf`. `(*cf).args` element at index 1 is the directive's
    // single argument, guaranteed present by NGX_CONF_TAKE1.
    unsafe {
        if cf.is_null() || conf.is_null() {
            return b"l402_invoice_rate_limit: null configuration pointer\0".as_ptr()
                as *mut c_char;
        }
        let conf = &mut *(conf as *mut ModuleConfig);
        let val = (*((*(*cf).args).elts as *mut ngx_str_t).add(1)).to_str().unwrap_or_default();
        match parse_rate_limit(val) {
            Some((max_req, window_secs)) => {
                conf.invoice_rate_limit = Some((max_req, window_secs));
                info!(
                    "Set invoice rate limit: {} requests per {}s",
                    max_req, window_secs
                );
            }
            None => {
                error!("Invalid l402_invoice_rate_limit value: '{}'", val);
                return b"l402_invoice_rate_limit: expected e.g. '5r/m', '10r/h', '2r/s', or '5'\0"
                    .as_ptr() as *mut c_char;
            }
        }
    }
    std::ptr::null_mut()
}
pub unsafe extern "C" fn ngx_http_l402_auto_detect_payment_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;
        let val = (*args.add(1)).to_str().unwrap_or_default().trim().to_lowercase();

        match val.as_str() {
            "on" | "true" | "1" | "yes" => {
                conf.auto_detect_payment = true;
                info!("⚙️ Enabled L402 auto-detect payment for this location");
            }
            "off" | "false" | "0" | "no" => {
                conf.auto_detect_payment = false;
                info!("⚙️ Disabled L402 auto-detect payment for this location");
            }
            _ => {
                error!("❌ Invalid auto_detect_payment configuration value: {}", val);
                return std::ptr::null_mut();
            }
        }
    }
    std::ptr::null_mut()
}
