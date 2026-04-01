use env_logger;
use hex;
use l402_middleware::middleware::L402Middleware;
use l402_middleware::{bolt12, cln, eclair, l402, lnclient, lnd, lnurl, macaroon_util, nwc, utils};
use log::{debug, error, info, warn};
use macaroon::Verifier;
use ngx::ffi::{
    nginx_version, ngx_array_push, ngx_command_t, ngx_conf_t, ngx_cycle_s, ngx_http_core_module,
    ngx_http_handler_pt, ngx_http_module_t, ngx_http_phases_NGX_HTTP_ACCESS_PHASE,
    ngx_http_request_t, ngx_int_t, ngx_log_s, ngx_module_t, ngx_str_t, ngx_uint_t, NGX_CONF_TAKE1,
    NGX_DECLINED, NGX_ERROR, NGX_HTTP_LOC_CONF, NGX_HTTP_MODULE, NGX_LOG_ERR, NGX_LOG_INFO, NGX_OK,
    NGX_RS_HTTP_LOC_CONF_OFFSET, NGX_RS_MODULE_SIGNATURE,
};
use ngx::http::{ngx_http_conf_get_module_main_conf, HTTPModule, Merge, MergeConfigError, Request};
use ngx::{ngx_log_error, ngx_null_command, ngx_string};
use r2d2::Pool;
use redis::Client as RedisClient;
use redis::Commands;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::c_char;
use std::ffi::CStr;
use std::os::raw::c_void;
use std::ptr::addr_of;
use std::sync::Arc;
use std::sync::Once;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tonic_openssl_lnd::lnrpc;

mod cashu;
mod cashu_redemption_logger;

static INIT: Once = Once::new();
static mut MODULE: Option<L402Module> = None;
/// Connection pool for Redis. Checked out connections are returned automatically on drop.
/// Pool size is configurable via REDIS_POOL_SIZE (default: cpu_count * 3, min 5, max 50).
static REDIS_POOL: OnceLock<Pool<RedisClient>> = OnceLock::new();

// Cache for LNURL clients - lazy initialization on first use per address
static LNURL_CLIENT_CACHE: OnceLock<
    tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<dyn lnclient::LNClient + Send>>>>,
> = OnceLock::new();

/// Get or create a cached LNURL client for the given address
/// This function is also used by cashu.rs for multi-tenant redemption
pub async fn get_or_create_lnurl_client(
    addr: &str,
) -> Result<Arc<tokio::sync::Mutex<dyn lnclient::LNClient + Send>>, String> {
    let cache = LNURL_CLIENT_CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));

    // Check if we already have a cached client
    {
        let cache_guard = cache.lock().await;
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
        root_key: std::env::var("ROOT_KEY")
            .unwrap_or_else(|_| "root_key".to_string())
            .as_bytes()
            .to_vec(),
    };

    match lnurl::LnAddressUrlResJson::new_client(&ln_client_config).await {
        Ok(ln_client) => {
            let client_arc = ln_client;
            // Cache the new client
            let mut cache_guard = cache.lock().await;
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

/// Check if a preimage has been used before (replay attack prevention)
/// Returns true if preimage is already used, false if it's new
fn is_preimage_used(preimage: &[u8]) -> bool {
    // If Redis is not configured, we can't track preimages (fallback to no protection)
    let Some(pool) = REDIS_POOL.get() else {
        warn!("⚠️ Redis not configured - preimage replay protection disabled");
        return false;
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("❌ Failed to get Redis connection from pool for preimage check: {}", e);
            return false;
        }
    };

    // Create a hash of the preimage for the key
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    let preimage_hash = hex::encode(hasher.finalize());
    let redis_key = format!("l402:preimage:{}", preimage_hash);

    // Check if key exists
    match conn.exists::<_, bool>(&redis_key) {
        Ok(exists) => {
            if exists {
                warn!("⚠️ Preimage replay attack detected: {}", preimage_hash);
            }
            exists
        }
        Err(e) => {
            error!("❌ Failed to check preimage in Redis: {}", e);
            false
        }
    }
}

/// Store a preimage as used with TTL (default 24 hours)
/// This prevents replay attacks by marking preimages as consumed
fn store_preimage_as_used(preimage: &[u8]) -> Result<(), String> {
    let pool = REDIS_POOL.get().ok_or("Redis not configured")?;

    let mut conn = pool
        .get()
        .map_err(|e| format!("Failed to get Redis connection from pool: {}", e))?;

    // Create a hash of the preimage for the key
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    let preimage_hash = hex::encode(hasher.finalize());
    let redis_key = format!("l402:preimage:{}", preimage_hash);

    // Get TTL from environment or default to 24 hours
    let ttl_seconds = std::env::var("L402_PREIMAGE_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(86400); // 24 hours default

    // Store with TTL (SETEX: SET with EXpire)
    conn.set_ex::<_, _, ()>(&redis_key, "used", ttl_seconds)
        .map_err(|e| format!("Failed to store preimage in Redis: {}", e))?;

    info!(
        "✅ Stored preimage as used: {} (TTL: {}s)",
        preimage_hash, ttl_seconds
    );
    Ok(())
}

/// Check if a Cashu token has been used before (replay attack prevention)
/// Returns true if token is already used, false if it's new
pub fn is_cashu_token_used(token: &str) -> bool {
    // If Redis is not configured, we can't track tokens (fallback to thread-local only)
    let Some(pool) = REDIS_POOL.get() else {
        warn!("⚠️ Redis not configured - Cashu token replay protection limited to memory");
        return false;
    };

    let mut conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("❌ Failed to get Redis connection from pool for Cashu token check: {}", e);
            return false;
        }
    };

    // Create a hash of the token for the key
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());
    let redis_key = format!("l402:cashu_token:{}", token_hash);

    // Check if key exists
    match conn.exists::<_, bool>(&redis_key) {
        Ok(exists) => {
            if exists {
                warn!(
                    "⚠️ Cashu token replay attack detected: {}",
                    &token_hash[..16]
                );
            }
            exists
        }
        Err(e) => {
            error!("❌ Failed to check Cashu token in Redis: {}", e);
            false
        }
    }
}

/// Store a Cashu token as used with TTL (default 24 hours)
/// This prevents replay attacks by marking tokens as consumed
pub fn store_cashu_token_as_used(token: &str) -> Result<(), String> {
    let pool = REDIS_POOL.get().ok_or("Redis not configured")?;

    let mut conn = pool
        .get()
        .map_err(|e| format!("Failed to get Redis connection from pool: {}", e))?;

    // Create a hash of the token for the key
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());
    let redis_key = format!("l402:cashu_token:{}", token_hash);

    // Get TTL from environment or default to 24 hours
    let ttl_seconds = std::env::var("L402_CASHU_TOKEN_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(86400); // 24 hours default

    // Store with TTL (SETEX: SET with EXpire)
    conn.set_ex::<_, _, ()>(&redis_key, "used", ttl_seconds)
        .map_err(|e| format!("Failed to store Cashu token in Redis: {}", e))?;

    info!(
        "✅ Stored Cashu token as used: {} (TTL: {}s)",
        &token_hash[..16],
        ttl_seconds
    );
    Ok(())
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
                Ok(manager) => {
                    match Pool::builder().max_size(pool_size).build(manager) {
                        Ok(pool) => {
                            if REDIS_POOL.set(pool).is_ok() {
                                info!(
                                    "✅ Redis connection pool ready (max_size={}) at {}",
                                    pool_size, redis_url
                                );
                            } else {
                                error!("❌ Failed to register Redis pool in OnceLock");
                            }
                        }
                        Err(e) => error!("❌ Failed to build Redis connection pool: {}", e),
                    }
                }
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
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
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
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
                }
            }
            "NWC" => {
                info!("🔧 Configuring NWC client");
                let uri = std::env::var("NWC_URI").unwrap_or_else(|_| "nwc_uri".to_string());
                info!("🔗 Using NWC URI: {}", uri);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: None,
                    cln_config: None,
                    nwc_config: Some(nwc::NWCOptions { uri }),
                    bolt12_config: None,
                    eclair_config: None,
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
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
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
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
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
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
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
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
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
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

    pub fn get_dynamic_price(&self, path: &str) -> i64 {
        if let Some(pool) = REDIS_POOL.get() {
            if let Ok(mut conn) = pool.get() {
                // Try to get price from Redis using the path as key
                let price: Option<i64> = conn.get(path).unwrap_or(None);
                return price.unwrap_or(0);
            }
        }

        0 // Return 0 if Redis is not configured or connection fails
    }

    pub fn get_dynamic_lnurl(&self, path: &str) -> Option<String> {
        if let Some(pool) = REDIS_POOL.get() {
            if let Ok(mut conn) = pool.get() {
                // Try to get lnurl from Redis using the path as key with "lnurl:" prefix
                let key = format!("lnurl:{}", path);
                let lnurl: Option<String> = conn.get(key).unwrap_or(None);
                return lnurl;
            }
        }
        None // Return None if Redis is not configured or connection fails
    }
}

impl HTTPModule for L402Module {
    type MainConf = ();
    type SrvConf = ();
    type LocConf = ModuleConfig;

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        info!("🚀 Initializing L402 module handler");
        let cmcf = ngx_http_conf_get_module_main_conf(cf, &*addr_of!(ngx_http_core_module));
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

#[derive(Debug, Default)]
pub struct ModuleConfig {
    enable: bool,
    amount_msat: i64,
    macaroon_timeout: i64,
    lnurl_addr: Option<String>,
    // (max_requests, window_secs): e.g. (5, 60) means 5 invoices per minute per IP per route.
    // None means rate limiting is disabled for this location.
    invoice_rate_limit: Option<(u32, u64)>,
}

pub static mut NGX_HTTP_L402_COMMANDS: [ngx_command_t; 6] = [
    ngx_command_t {
        name: ngx_string!("l402"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_set),
        conf: NGX_RS_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_amount_msat_default"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_amount_set),
        conf: NGX_RS_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_macaroon_timeout"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_timeout_set),
        conf: NGX_RS_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_lnurl_addr"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_lnurl_set),
        conf: NGX_RS_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_invoice_rate_limit"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_invoice_rate_limit_set),
        conf: NGX_RS_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_null_command!(),
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
        Ok(())
    }
}

pub unsafe extern "C" fn l402_access_handler_wrapper(request: *mut ngx_http_request_t) -> isize {
    let log = unsafe { &mut *(*(*request).connection).log };
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
    ) = unsafe {
        let r = &mut *request;
        let auth_header = if !r.headers_in.authorization.is_null() {
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

        // Get module config to check if L402 is enabled
        let loc_conf = (*r).loc_conf;
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

        (
            auth_header,
            uri.clone(),
            method,
            amount_msat,
            macaroon_timeout,
            lnurl_addr,
            invoice_rate_limit,
        )
    };

    let mut request_path = uri.clone();
    if request_path.contains(".html") || request_path.ends_with('/') {
        if let Some(pos) = request_path.rfind('/') {
            request_path = request_path[..pos].to_string();
        }
    }
    let caveats = vec![format!("RequestPath = {}", request_path)];

    // Get dynamic price from Redis
    let module = match unsafe { MODULE.as_ref() } {
        Some(m) => m,
        None => {
            error!("Module not initialized — returning 500");
            return 500;
        }
    };
    let dynamic_amount = module.get_dynamic_price(&request_path);
    let final_amount = if dynamic_amount > 0 {
        dynamic_amount
    } else {
        amount_msat
    };

    // Get dynamic LNURL from Redis (takes precedence over nginx config)
    let dynamic_lnurl = module.get_dynamic_lnurl(&request_path);
    let final_lnurl_addr = dynamic_lnurl.or(lnurl_addr);

    let result = l402_access_handler(
        auth_header,
        uri,
        method,
        final_amount,
        caveats.clone(),
        final_lnurl_addr.clone(),
    );

    // Only set L402 header if result is 402
    if result == 402 {
        if let Some((max_requests, window_secs)) = invoice_rate_limit {
            let client_ip = get_client_ip(request);
            if !check_invoice_rate_limit(&client_ip, &request_path, max_requests, window_secs) {
                ngx_log_error!(
                    NGX_LOG_ERR,
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

        // Use a lazily initialized static runtime
        static RUNTIME: OnceLock<Runtime> = OnceLock::new();
        let rt = RUNTIME.get_or_init(|| {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("FATAL: failed to create tokio runtime: {}", e);
                    std::process::abort();
                }
            }
        });

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
        let header_result = rt.block_on(async {
            module
                .get_l402_header(
                    caveats.clone(),
                    final_amount,
                    macaroon_timeout,
                    final_lnurl_addr.clone(),
                )
                .await
        });

        match header_result {
            Some(header_value) => unsafe {
                ngx_log_error!(
                    NGX_LOG_INFO,
                    log_ref,
                    "Setting L402/WWW-Authenticate header"
                );
                let req = Request::from_ngx_http_request(request);
                req.add_header_out("WWW-Authenticate", &header_value);
            },
            None => {
                ngx_log_error!(NGX_LOG_ERR, log_ref, "Failed to get L402 header");
                return 500; // Return server error if we couldn't get the header
            }
        }
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
) -> isize {
    let module = match unsafe { MODULE.as_ref() } {
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
        debug!("🔑 Found authorization header");
        debug!("🔑 Authorization header: {}", auth_str);

        if auth_str.starts_with("Cashu ") {
            let token = auth_str.trim_start_matches("Cashu ").trim().to_string();

            // Use a lazily initialized static runtime
            static RUNTIME: OnceLock<Runtime> = OnceLock::new();
            let rt = RUNTIME.get_or_init(|| {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("FATAL: failed to create tokio runtime: {}", e);
                        std::process::abort();
                    }
                }
            });

            let verify_result = rt.block_on(async {
                module
                    .verify_cashu_token(&token, amount_msat, lnurl_addr.clone())
                    .await
            });

            match verify_result {
                Ok(true) => {
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
            match utils::parse_l402_header(&auth_str) {
                Ok((mac, preimage)) => {
                    // Check for replay attack - has this preimage been used before?
                    if is_preimage_used(&preimage.0) {
                        error!("🚨 Replay attack detected: preimage already used");
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
                        // Return true for predicates we don't need to validate
                        // This allows other predicates to pass through
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

                            // Store preimage as used to prevent replay attacks
                            if let Err(e) = store_preimage_as_used(&preimage.0) {
                                error!("⚠️ Failed to store preimage in Redis: {}", e);
                                // Continue anyway - verification was successful
                            }

                            return NGX_DECLINED as isize;
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

    let log = (*cycle).log;

    // Initialize logger - this is critical for RUST_LOG to work
    let _ = env_logger::try_init();

    info!("🚀 Starting L402 module initialization");
    ngx_log_error!(NGX_LOG_INFO, log, "Starting module initialization");

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

    INIT.call_once(|| {
        info!("🔄 Initializing runtime and L402Module");
        match std::panic::catch_unwind(|| {
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

            unsafe {
                MODULE = Some(module);
            }
            info!("✅ L402Module initialized successfully");
        }) {
            Ok(_) => (),
            Err(e) => {
                error!("💥 Panic during initialization: {:?}", e);
                unsafe {
                    MODULE = None;
                }
            }
        }
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

        let _module = unsafe { MODULE.as_ref().expect("Module not initialized") };

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

pub unsafe extern "C" fn ngx_http_l402_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val = (*args.add(1)).to_str();

        // set default value optionally
        conf.enable = false;

        if val.len() == 2 && val.eq_ignore_ascii_case("on") {
            conf.enable = true;
        } else if val.len() == 3 && val.eq_ignore_ascii_case("off") {
            conf.enable = false;
        }
    };

    std::ptr::null_mut()
}

pub unsafe extern "C" fn ngx_http_l402_amount_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val = (*args.add(1)).to_str();

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
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val = (*args.add(1)).to_str();

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
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val = (*args.add(1)).to_str().trim();

        let lnurl_addr = if !val.is_empty() {
            val.to_string()
        } else {
            std::env::var("LNURL_ADDRESS").unwrap_or_else(|_| "admin@getalby.com".to_string())
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
            let val = (*r.headers_in.x_real_ip).value.to_str().trim().to_string();
            if !val.is_empty() {
                return val;
            }
        }

        // X-Forwarded-For: "client, proxy1, proxy2" — leftmost is the origin
        if !r.headers_in.x_forwarded_for.is_null() {
            let val = (*r.headers_in.x_forwarded_for).value.to_str();
            if let Some(ip) = val.split(',').next() {
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
        (*conn).addr_text.to_str().to_string()
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

    let key = format!("l402:invoice_rate:{}:{}", ip, path);

    let count: u64 = match conn.incr::<_, _, u64>(&key, 1i64) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to increment invoice rate limit counter: {}", e);
            return true;
        }
    };

    // only set TTL on first hit to avoid extending the window
    if count == 1 {
        if let Err(e) = conn.expire::<_, bool>(&key, window_secs as i64) {
            error!("Failed to set invoice rate limit TTL: {}", e);
        }
    }

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
        let val = (*((*(*cf).args).elts as *mut ngx_str_t).add(1)).to_str();
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
