use env_logger;
use l402_middleware::middleware::L402Middleware;
use l402_middleware::{cln, l402, lnclient, lnd, lnurl, macaroon_util, nwc, utils};
use log::{debug, error, info, warn};
use macaroon::Verifier;
use ngx::ffi::{
    ngx_array_push, ngx_command_t, ngx_conf_t, ngx_cycle_s, ngx_http_core_module,
    ngx_http_handler_pt, ngx_http_module_t, ngx_http_phases_NGX_HTTP_ACCESS_PHASE,
    ngx_http_request_t, ngx_int_t, ngx_log_s, ngx_module_t, ngx_str_t, ngx_uint_t, NGX_CONF_TAKE1,
    NGX_DECLINED, NGX_ERROR, NGX_HTTP_LOC_CONF, NGX_HTTP_MODULE, NGX_LOG_ERR, NGX_LOG_INFO, NGX_OK,
    NGX_RS_HTTP_LOC_CONF_OFFSET, NGX_RS_MODULE_SIGNATURE,
    // Added for HTML response
    ngx_buf_t, ngx_chain_t, ngx_pcalloc, ngx_palloc, ngx_http_send_header, ngx_http_output_filter,
};
use ngx::http::{ngx_http_conf_get_module_main_conf, HTTPModule, Merge, MergeConfigError, Request};
use ngx::{ngx_log_error, ngx_null_command, ngx_string};
use redis::Client as RedisClient;
use redis::Commands;
use std::collections::HashMap;
use std::ffi::c_char;
use std::ffi::CStr;
use std::os::raw::c_void;
use std::ptr::addr_of;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Once;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;
use tonic_openssl_lnd::lnrpc;

mod html;
mod cashu;
mod cashu_redemption_logger;

static INIT: Once = Once::new();
static mut MODULE: Option<L402Module> = None;
static REDIS_CLIENT: OnceLock<Mutex<RedisClient>> = OnceLock::new();

// Cache for LNURL clients - lazy initialization on first use per address
static LNURL_CLIENT_CACHE: OnceLock<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<dyn lnclient::LNClient + Send>>>>> = OnceLock::new();

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
        lnurl_config: Some(lnurl::LNURLOptions { address: addr.to_string() }),
        nwc_config: None,
        cln_config: None,
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

pub struct L402Module {
    middleware: L402Middleware,
}

impl L402Module {
    pub async fn new() -> Self {
        info!("🚀 Creating new L402Module");

        // Initialize Redis client if URL is configured
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            match RedisClient::open(redis_url.clone()) {
                Ok(redis_client) => {
                    if let Ok(_) = REDIS_CLIENT.set(Mutex::new(redis_client)) {
                        info!("✅ Connected to Redis at {}", redis_url);
                    } else {
                        error!("❌ Failed to set Redis client in OnceLock");
                    }
                }
                Err(e) => error!("❌ Failed to create Redis client: {}", e),
            }
        } else {
            info!("ℹ️ No Redis URL configured, dynamic pricing disabled");
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
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
                }
            }
            "LND" => {
                info!("🔧 Configuring LND client");
                let address =
                    std::env::var("LND_ADDRESS").unwrap_or_else(|_| "localhost:10009".to_string());
                info!("🔗 Using LND address: {}", address);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: Some(lnd::LNDOptions {
                        address,
                        macaroon_file: std::env::var("MACAROON_FILE_PATH")
                            .unwrap_or_else(|_| "admin.macaroon".to_string()),
                        cert_file: std::env::var("CERT_FILE_PATH")
                            .unwrap_or_else(|_| "tls.cert".to_string()),
                    }),
                    lnurl_config: None,
                    nwc_config: None,
                    cln_config: None,
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
                .unwrap()
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

    pub async fn verify_cashu_token(&self, token: &str, amount_msat: i64, lnurl_addr: Option<String>) -> Result<bool, String> {
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
        if let Some(redis_client) = REDIS_CLIENT.get() {
            if let Ok(mut conn) = redis_client
                .lock()
                .expect("Failed to lock Redis client")
                .get_connection()
            {
                // Try to get price from Redis using the path as key
                let price: Option<i64> = conn.get(path).unwrap_or(None);
                return price.unwrap_or(0); // Return 0 if no price found
            }
        }
        0 // Return 0 if Redis is not configured or connection fails
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
}

pub static mut NGX_HTTP_L402_COMMANDS: [ngx_command_t; 5] = [
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
    version: 1028000 as ngx_uint_t,
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
        Ok(())
    }
}

/// Parses a `WWW-Authenticate` header value to extract the `macaroon` and `invoice` fields.
///
/// # Arguments
///
/// * `header` - A string slice representing the value of a `WWW-Authenticate` HTTP header.
///   The function expects the header to contain fields in the format: `macaroon="..."` and `invoice="..."`.
///
/// # Returns
///
/// A tuple `(macaroon, invoice)` where each element is a `String` containing the value of the respective field.
/// If a field is missing or malformed, its value in the tuple will be an empty string.
///
/// # Example
///
/// ```
/// let header = r#"L402 macaroon="abc", invoice="lnbc123""#;
/// let (macaroon, invoice) = parse_www_authenticate(header);
/// assert_eq!(macaroon, "abc");
/// assert_eq!(invoice, "lnbc123");
/// ```
fn parse_www_authenticate(header: &str) -> (String, String) { // (macaroon, invoice)
    // Parse macaroon
    let macaroon = if let Some(mac_start) = header.find("macaroon=\"") {
        let mac_start = mac_start + 10;
        if let Some(mac_end_rel) = header[mac_start..].find("\"") {
            let mac_end = mac_start + mac_end_rel;
            header[mac_start..mac_end].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    // Parse invoice
    let invoice = if let Some(inv_start) = header.find("invoice=\"") {
        let inv_start = inv_start + 9;
        if let Some(inv_end_rel) = header[inv_start..].find("\"") {
            let inv_end = inv_start + inv_end_rel;
            header[inv_start..inv_end].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    (macaroon, invoice)
}

/// Sends an HTML response with status 402 to the given nginx HTTP request.
///
/// # Safety
///
/// This function is unsafe because it directly manipulates raw pointers and nginx FFI structures.
/// The caller must ensure that:
/// - `r` is a valid, non-null pointer to an `ngx_http_request_t` structure allocated and managed by nginx.
/// - The function is called from the correct nginx request handling context.
/// - The memory pool associated with `r` is valid for the duration of this call.
/// - No concurrent modifications are made to the request or its memory pool while this function executes.
///
/// # Parameters
/// - `r`: A mutable pointer to an nginx HTTP request (`ngx_http_request_t`). Must be valid and non-null.
/// - `html`: The HTML content to send as the response body. The function will copy this data into nginx-managed memory.
///
/// # Return Value
/// Returns the result of `ngx_http_output_filter` as an `isize`. Returns `NGX_ERROR` on allocation or send errors, or the result of the output filter otherwise.
///
/// # Errors
/// Returns `NGX_ERROR` if memory allocation fails or if sending headers fails.
///
/// # Side Effects
/// - Modifies the response status, content type, and content length of the nginx request.
/// - Allocates memory from the nginx request pool.
/// - Sends the response headers and body to the client.
unsafe fn send_html_response(r: *mut ngx_http_request_t, html: String) -> isize {
    // Set Status
    (*r).headers_out.status = 402;
    
    // Set Content-Type
    let ct = "text/html";
    let ct_ptr = ngx::ffi::ngx_palloc((*r).pool, ct.len()) as *mut u8;
    if ct_ptr.is_null() {
        return NGX_ERROR as isize;
    }
    std::ptr::copy_nonoverlapping(ct.as_ptr(), ct_ptr, ct.len());
    (*r).headers_out.content_type.len = ct.len();
    (*r).headers_out.content_type.data = ct_ptr;
    
    // Set Content-Length
    (*r).headers_out.content_length_n = html.len() as i64;

    // Send Headers
    if ngx::ffi::ngx_http_send_header(r) == NGX_ERROR as isize {
        return NGX_ERROR as isize;
    }

    // Allocate buffer
    let pool = (*r).pool;
    let b = ngx::ffi::ngx_pcalloc(pool, std::mem::size_of::<ngx::ffi::ngx_buf_t>()) as *mut ngx::ffi::ngx_buf_t;
    if b.is_null() {
        return NGX_ERROR as isize;
    }

    // Copy data to buffer (must be alive or allocated in pool)
    let data_ptr = ngx::ffi::ngx_palloc(pool, html.len()) as *mut u8;
    if data_ptr.is_null() {
        return NGX_ERROR as isize;
    }
    std::ptr::copy_nonoverlapping(html.as_ptr(), data_ptr, html.len());

    (*b).pos = data_ptr;
    (*b).last = data_ptr.add(html.len());
    (*b).memory = 1; 
    (*b).last_buf = 1; 

    // Create chain
    let mut out = ngx::ffi::ngx_chain_t {
        buf: b,
        next: std::ptr::null_mut(),
    };

    ngx::ffi::ngx_http_output_filter(r, &mut out)
}

pub unsafe extern "C" fn l402_access_handler_wrapper(request: *mut ngx_http_request_t) -> isize {
    let log = unsafe { &mut *(*(*request).connection).log };
    let log_ref = log as *mut ngx_log_s;

    // Check if L402 is enabled for this location
    let (auth_header, uri, method, amount_msat, macaroon_timeout, lnurl_addr) = unsafe {
        let r = &mut *request;
        let auth_header = if !r.headers_in.authorization.is_null() {
            Some(
                CStr::from_ptr((*r.headers_in.authorization).value.data as *const i8)
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
            return NGX_DECLINED.try_into().unwrap();
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

        (
            auth_header,
            uri.clone(),
            method,
            amount_msat,
            macaroon_timeout,
            lnurl_addr,
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
    let module = unsafe { MODULE.as_ref().expect("Module not initialized") };
    let dynamic_amount = module.get_dynamic_price(&request_path);
    let final_amount = if dynamic_amount > 0 {
        dynamic_amount
    } else {
        amount_msat
    };

    let result = l402_access_handler(auth_header, uri, method, final_amount, caveats.clone(), lnurl_addr.clone());

    // Only set L402 header if result is 402
    if result == 402 {
        // Use a lazily initialized static runtime
        static RUNTIME: OnceLock<Runtime> = OnceLock::new();
        let rt = RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread() // Use single-threaded runtime for less overhead
                .enable_all()
                .build()
                .expect("tokio runtime init")
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
                .get_l402_header(caveats.clone(), final_amount, macaroon_timeout, lnurl_addr.clone())
                .await
        });

// Helper to parse WWW-Authenticate header value
                // Fallback: Check User-Agent for Mozilla/Chrome/Safari
                 if !is_html_request && !(*request).headers_in.user_agent.is_null() {
                    let ua = CStr::from_ptr((*(*request).headers_in.user_agent).value.data as *const i8)
                        .to_str().unwrap_or("").to_lowercase();
                    if ua.contains("mozilla") || ua.contains("chrome") || ua.contains("safari") {
                        is_html_request = true;
                    }
                }

                ngx_log_error!(
                    NGX_LOG_INFO,
                    log_ref,
                    "Setting L402/WWW-Authenticate header (is_html={})",
                    is_html_request
                );
                
                let req = Request::from_ngx_http_request(request);
                req.add_header_out("WWW-Authenticate", &header_value);

                if is_html_request {
                    let (macaroon, invoice) = parse_www_authenticate(&header_value);
                    if !macaroon.is_empty() && !invoice.is_empty() {
                         let html_body = html::get_payment_html(
                             &invoice, 
                             &macaroon, 
                             cashu_ecash_support, 
                             final_amount
                         );
                         // Since we are creating a response, we should return the result of sending it.
                         // l402_access_handler_wrapper returns isize. 
                         // NGX_OK or NGX_DONE stops phase processing.
                         // But send_html_response calls output_filter which returns ngx_int_t (isize).
                         let ret = send_html_response(request, html_body);
                         
                         // We must ensure Nginx knows we are done.
                         // Usually return NGX_OK (0) or NGX_DONE (-4).
                         // If output_filter returns OK, we return OK.
                         return ret; 
                    }
                }
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
    let module = unsafe { MODULE.as_ref().expect("Module not initialized") };

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
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime init")
            });

            let verify_result =
                rt.block_on(async { module.verify_cashu_token(&token, amount_msat, lnurl_addr.clone()).await });

            match verify_result {
                Ok(true) => {
                    return NGX_DECLINED.try_into().unwrap();
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
                            return NGX_DECLINED.try_into().unwrap();
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
            let module = rt.block_on(async { L402Module::new().await });

            // Initialize LN client for cashu redemption
            let ln_client = module.middleware.ln_client.clone();
            let ln_client_type = std::env::var("LN_CLIENT_TYPE").unwrap_or_else(|_| "LNURL".to_string());
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

        let module = unsafe { MODULE.as_ref().expect("Module not initialized") };

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
                    let result = thread_rt.block_on(async {
                        cashu::redeem_to_lightning().await
                    });

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
