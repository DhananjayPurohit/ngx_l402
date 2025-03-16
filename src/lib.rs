use ngx::ffi::{
    ngx_command_t, ngx_cycle_s, ngx_http_request_t, ngx_module_t, ngx_str_t,
    NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_MODULE, NGX_RS_HTTP_LOC_CONF_OFFSET,
    NGX_RS_MODULE_SIGNATURE, ngx_http_module_t, ngx_http_core_module, ngx_array_push, 
    ngx_http_handler_pt, ngx_conf_t, ngx_uint_t, NGX_OK, NGX_DECLINED, NGX_ERROR,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, NGX_LOG_INFO, NGX_LOG_ERR, ngx_log_s,
    ngx_table_elt_t, ngx_list_push, ngx_http_headers_out_t
};
use ngx::http::{HTTPModule, ngx_http_conf_get_module_main_conf, Merge, MergeConfigError, Request};
use ngx::{ngx_null_command, ngx_string, ngx_log_error};
use l402_middleware::middleware::L402Middleware;
use std::sync::Arc;
use std::os::raw::c_void;
use std::ffi::c_char;
use std::ptr::addr_of;
use reqwest::Client;
use l402_middleware::{lnclient, lnurl, lnd, nwc, l402, utils, macaroon_util};
use std::ffi::CStr;
use std::sync::Once;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use once_cell::sync::Lazy;
use tonic_openssl_lnd::lnrpc;
use std::sync::mpsc;
use std::thread;
use std::fs;
use std::sync::OnceLock;

const SATS_PER_BTC: i64 = 100_000_000;
const MIN_SATS_TO_BE_PAID: i64 = 1;
const MSAT_PER_SAT: i64 = 1000;

static INIT: Once = Once::new();
static mut MODULE: Option<L402Module> = None;
static mut RUNTIME: Option<Runtime> = None;

#[derive(Clone)]
pub struct FiatRateConfig {
    pub currency: String,
    pub amount: f64,
}

impl FiatRateConfig {
    pub async fn fiat_to_btc_amount_func(&self) -> i64 {
        println!("Converting {} {} to BTC", self.amount, self.currency);
        
        if self.amount <= 0.0 {
            println!("Amount is <= 0, returning minimum sats");
            return MIN_SATS_TO_BE_PAID * MSAT_PER_SAT;
        }

        let url = format!(
            "https://blockchain.info/tobtc?currency={}&value={}",
            self.currency, self.amount
        );
        println!("Making request to: {}", url);

        match Client::new().get(&url).send().await {
            Ok(res) => {
                let body = res.text().await.unwrap_or_else(|_| MIN_SATS_TO_BE_PAID.to_string());
                match body.parse::<f64>() {
                    Ok(amount_in_btc) => ((SATS_PER_BTC as f64 * amount_in_btc) * MSAT_PER_SAT as f64) as i64,
                    Err(_) => MIN_SATS_TO_BE_PAID * MSAT_PER_SAT,
                }
            }
            Err(_) => MIN_SATS_TO_BE_PAID * MSAT_PER_SAT,
        }
    }
}

pub struct L402Module {
    config: Arc<FiatRateConfig>,
    middleware: L402Middleware,
}

impl L402Module {
    pub async fn new() -> Self {
        println!("Creating new L402Module");
        // Get environment variables
        let ln_client_type = std::env::var("LN_CLIENT_TYPE").unwrap_or_else(|_| "LNURL".to_string());
        println!("Using LN client type: {}", ln_client_type);
        
        let ln_client_config = match ln_client_type.as_str() {
            "LNURL" => {
                println!("Configuring LNURL client");
                let address = std::env::var("LNURL_ADDRESS").unwrap_or_else(|_| "lnurl_address".to_string());
                println!("Using LNURL address: {}", address);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: Some(lnurl::LNURLOptions {
                        address,
                    }),
                    nwc_config: None,
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
                }
            },
            "LND" => {
                println!("Configuring LND client");
                let address = std::env::var("LND_ADDRESS").unwrap_or_else(|_| "localhost:10009".to_string());
                println!("Using LND address: {}", address);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: Some(lnd::LNDOptions {
                        address,
                        macaroon_file: std::env::var("MACAROON_FILE_PATH").unwrap_or_else(|_| "admin.macaroon".to_string()),
                        cert_file: std::env::var("CERT_FILE_PATH").unwrap_or_else(|_| "tls.cert".to_string()),
                    }),
                    lnurl_config: None,
                    nwc_config: None,
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
                }
            },
            "NWC" => {
                println!("Configuring NWC client");
                let uri = std::env::var("NWC_URI").unwrap_or_else(|_| "nwc_uri".to_string());
                println!("Using NWC URI: {}", uri);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: None,
                    nwc_config: Some(nwc::NWCOptions {
                        uri,
                    }),
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
                }
            },
            _ => {
                println!("Unknown client type, defaulting to LNURL");
                let address = std::env::var("LNURL_ADDRESS").unwrap_or_else(|_| "lnurl_address".to_string());
                println!("Using LNURL address: {}", address);
                lnclient::LNClientConfig {
                    ln_client_type,
                    lnd_config: None,
                    lnurl_config: Some(lnurl::LNURLOptions {
                        address,
                    }),
                    nwc_config: None,
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
                }
            },
        };

        let config = FiatRateConfig {
            currency: std::env::var("CURRENCY").unwrap_or_else(|_| "USD".to_string()),
            amount: std::env::var("AMOUNT")
                .unwrap_or_else(|_| "0.01".to_string())
                .parse()
                .unwrap_or(0.01),
        };
        println!("Created FiatRateConfig: {} {}", config.amount, config.currency);

        let config = Arc::new(config);
        let fiat_rate_config = Arc::clone(&config);

        println!("Creating L402 middleware");
        let middleware = L402Middleware::new_l402_middleware(
            ln_client_config.clone(),
            Arc::new(move |_| {
                let fiat_config = Arc::clone(&fiat_rate_config);
                Box::pin(async move {
                    fiat_config.fiat_to_btc_amount_func().await
                })
            }),
            Arc::new(|req| {
                vec![format!("RequestPath = {}", req.uri().path())]
            }),
        ).await.expect("Failed to create middleware");

        Self {
            config,
            middleware,
        }
    }

    pub async fn get_l402_header(&self, caveats: Vec<String>) -> Option<String> {
        let value_msat = self.config.fiat_to_btc_amount_func().await;
        let ln_invoice = lnrpc::Invoice {
            value_msat: value_msat,
            memo: l402::L402_HEADER.to_string(),
            ..Default::default()
        };

        let ln_client_conn = lnclient::LNClientConn {
            ln_client: self.middleware.ln_client.clone(),
        };

        println!("invoice value: {}", value_msat);
        
        match ln_client_conn.generate_invoice(ln_invoice).await {
            Ok((invoice, payment_hash)) => {
                println!("invoice: {}", invoice);
                
                match macaroon_util::get_macaroon_as_string(payment_hash, caveats, self.middleware.root_key.clone()) {
                    Ok(macaroon_string) => {
                        let header_value = format!("L402 macaroon=\"{}\", invoice=\"{}\"", macaroon_string, invoice);
                        println!("header value: {}", header_value);
                        Some(header_value)
                    },
                    Err(error) => {
                        println!("Error generating macaroon: {}", error);
                        None
                    }
                }
            },
            Err(e) => {
                println!("Error generating invoice: {:?}", e);
                None
            }
        }
    }
}

impl HTTPModule for L402Module {
    type MainConf = ();
    type SrvConf = ();
    type LocConf = ModuleConfig;

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        println!("Initializing L402 module handler");
        let cmcf = ngx_http_conf_get_module_main_conf(cf, &*addr_of!(ngx_http_core_module));
        let h = ngx_array_push(&mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_ACCESS_PHASE as usize].handlers) as *mut ngx_http_handler_pt;

        if h.is_null() {
            return NGX_ERROR as ngx_int_t;
        }
        // set an access phase handler for l402
        *h = Some(l402_access_handler_wrapper);
        NGX_OK as ngx_int_t
    }
}

#[derive(Debug, Default)]
pub struct ModuleConfig {
    enable: bool,
}

pub static mut NGX_HTTP_L402_COMMANDS: [ngx_command_t; 2] = [
    ngx_command_t {
        name: ngx_string!("l402"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_set),
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
    version: 1027003 as ngx_uint_t,
    signature: NGX_RS_MODULE_SIGNATURE.as_ptr() as *const c_char,

    ctx: &NGX_HTTP_L402_MODULE_CTX as *const _ as *mut c_void,
    commands: unsafe { &NGX_HTTP_L402_COMMANDS[0] as *const _ as *mut _ },
    type_: NGX_HTTP_MODULE as usize,

    init_master: None,
    // init_module: None,
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
        Ok(())
    }
}

pub unsafe extern "C" fn l402_access_handler_wrapper(request: *mut ngx_http_request_t) -> isize {

    let log = unsafe { &mut *(*(*request).connection).log };
    let log_ref = log as *mut ngx_log_s;

    // Check if L402 is enabled for this location
    let (auth_header, uri, method) = unsafe {
        let r = &mut *request;
        let auth_header = if !r.headers_in.authorization.is_null() {
            Some(CStr::from_ptr((*r.headers_in.authorization).value.data as *const i8)
                .to_str()
                .unwrap_or("")
                .to_string())
        } else {
            None
        };
        
        let uri = r.uri.to_string();
        let method = r.method as u32;

        // Get module config to check if L402 is enabled
        let loc_conf = (*r).loc_conf;
        let conf = &*((*loc_conf.offset(ngx_http_l402_module.ctx_index as isize)) as *const ModuleConfig);
        if !conf.enable {
            ngx_log_error!(NGX_LOG_INFO, log_ref, "L402 is disabled for this location");
            return NGX_DECLINED.try_into().unwrap();
        }

        (auth_header, uri, method)
    };

    let mut request_path = uri.clone();
    if request_path.contains(".html") || request_path.ends_with('/') {
        if let Some(pos) = request_path.rfind('/') {
            request_path = request_path[..pos].to_string();
        }
    }
    let caveats = vec![format!("RequestPath = {}", request_path)];

    let result = l402_access_handler(auth_header, uri, method, caveats.clone());
    
    // Only set L402 header if result is 402
    if result == 402 {
        let module = unsafe { MODULE.as_ref().expect("Module not initialized") };
        
        // Create a new runtime for this request
        let rt = Runtime::new().expect("Failed to create runtime");
        
        // Add timeout to prevent socket hang up
        let header_value = rt.block_on(async {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10), // 10 second timeout
                module.get_l402_header(caveats.clone())
            ).await {
                Ok(result) => result,
                Err(_) => {
                    ngx_log_error!(NGX_LOG_ERR, log_ref, "Timeout occurred while getting L402 header");
                    None
                }
            }
        });
        
        if let Some(header_value) = header_value {
            unsafe {
                ngx_log_error!(NGX_LOG_INFO, log_ref, "Setting L402 header");
                
                let req = Request::from_ngx_http_request(request);
                req.add_header_out("WWW-Authenticate", &header_value);
            }
        } else {
            ngx_log_error!(NGX_LOG_ERR, log_ref, "Failed to get L402 header");
            return 500; // Return server error if we couldn't get the header
        }
    }
    
    result
}

pub fn l402_access_handler(auth_header: Option<String>, uri: String, method: u32, caveats: Vec<String>) -> isize {
    let module = unsafe {
        MODULE.as_ref().expect("Module not initialized")
    };

    println!("Processing request - Method: {:?}, URI: {:?}", method, uri);
    
    if let Some(auth_str) = auth_header {
        println!("Found authorization header");
        println!("Authorization: {}", auth_str);

        match utils::parse_l402_header(&auth_str) {
            Ok((mac, preimage)) => {
                println!("Successfully parsed L402 header");
                match l402::verify_l402(&mac, caveats.clone(), module.middleware.root_key.clone(), preimage) {
                    Ok(_) => {
                        println!("L402 verification successful");
                        return NGX_DECLINED.try_into().unwrap();
                    },
                    Err(e) => {
                        println!("L402 verification failed: {:?}", e);
                        return 500;
                    }
                }
            },
            Err(e) => {
                println!("Failed to parse L402 header: {:?}", e);
                return 500;
            }
        }
    }

    println!("No authorization header found, sending L402 challenge");
    402
}

pub unsafe extern "C" fn init_module(cycle: *mut ngx_cycle_s) -> isize {
    println!("Starting module initialization");
    
    if cycle.is_null() {
        println!("Error: Cycle pointer is null");
        return -1;
    }

    INIT.call_once(|| {
        println!("Initializing runtime and L402Module");
        match std::panic::catch_unwind(|| {
            let rt = Runtime::new().expect("Failed to create runtime");
            let module = rt.block_on(async {
                L402Module::new().await
            });
            
            unsafe { 
                RUNTIME = Some(rt);
                MODULE = Some(module);
            }
            
            println!("L402Module initialized successfully");
        }) {
            Ok(_) => (),
            Err(e) => {
                println!("Panic during initialization: {:?}", e);
                unsafe {
                    RUNTIME = None;
                    MODULE = None;
                }
            }
        }
    });

    println!("Module initialization complete");
    0
}

pub unsafe extern "C" fn ngx_http_l402_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void
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
