use ngx::ffi::{
    ngx_command_t, ngx_cycle_s, ngx_http_request_t, ngx_module_t, ngx_str_t,
    NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_MODULE, NGX_RS_HTTP_LOC_CONF_OFFSET,
    NGX_RS_MODULE_SIGNATURE, ngx_http_module_t, ngx_http_core_module, ngx_array_push, 
    ngx_http_handler_pt, ngx_conf_t, ngx_uint_t, NGX_OK, NGX_DECLINED, NGX_ERROR,
    ngx_http_phases_NGX_HTTP_ACCESS_PHASE, ngx_int_t, NGX_LOG_INFO, NGX_LOG_ERR, ngx_log_s
};
use ngx::http::{HTTPModule, ngx_http_conf_get_module_main_conf, Merge, MergeConfigError, Request};
use ngx::{ngx_null_command, ngx_string, ngx_log_error};
use l402_middleware::middleware::L402Middleware;
use std::sync::Arc;
use std::os::raw::c_void;
use std::ffi::c_char;
use std::ptr::addr_of;
use l402_middleware::{lnclient, lnurl, lnd, nwc, l402, utils, macaroon_util};
use std::ffi::CStr;
use std::sync::Once;
use tokio::runtime::Runtime;
use tonic_openssl_lnd::lnrpc;
use std::sync::OnceLock;

mod cashu;

static INIT: Once = Once::new();
static mut MODULE: Option<L402Module> = None;

pub struct L402Module {
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

        println!("Creating L402 middleware");
        let middleware = L402Middleware::new_l402_middleware(
            ln_client_config.clone(),
            Arc::new(move |_| {
                Box::pin(async move {
                    0   // Placeholder value, declaring for type inference
                })
            }),
            Arc::new(|req| {
                vec![format!("RequestPath = {}", req.uri().path())]
            }),
        ).await.expect("Failed to create middleware");

        Self {
            middleware,
        }
    }

    pub async fn get_l402_header(&self, caveats: Vec<String>, amount_msat: i64) -> Option<String> {
        let ln_invoice = lnrpc::Invoice {
            value_msat: amount_msat,
            memo: l402::L402_HEADER.to_string(),
            ..Default::default()
        };

        let ln_client_conn = lnclient::LNClientConn {
            ln_client: self.middleware.ln_client.clone(),
        };

        println!("invoice value: {}", amount_msat);
        
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

    pub async fn verify_cashu_token(&self, token: &str, amount_msat: i64) -> Result<bool, String> {
        cashu::verify_cashu_token(token, amount_msat).await
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
    amount_msat: i64,
}

pub static mut NGX_HTTP_L402_COMMANDS: [ngx_command_t; 3] = [
    ngx_command_t {
        name: ngx_string!("l402"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_set),
        conf: NGX_RS_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: std::ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("l402_amount_msat"),
        type_: (NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t,
        set: Some(ngx_http_l402_amount_set),
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
        Ok(())
    }
}

pub unsafe extern "C" fn l402_access_handler_wrapper(request: *mut ngx_http_request_t) -> isize {
    let log = unsafe { &mut *(*(*request).connection).log };
    let log_ref = log as *mut ngx_log_s;
    
    // Check if L402 is enabled for this location
    let (auth_header, uri, method, amount_msat) = unsafe {
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

        let amount_msat = conf.amount_msat;
        if amount_msat <= 0 {
            ngx_log_error!(NGX_LOG_INFO, log_ref, "L402 amount_msat is not set or invalid");
            return 500;
        }

        (auth_header, uri, method, amount_msat)
    };

    let mut request_path = uri.clone();
    if request_path.contains(".html") || request_path.ends_with('/') {
        if let Some(pos) = request_path.rfind('/') {
            request_path = request_path[..pos].to_string();
        }
    }
    let caveats = vec![format!("RequestPath = {}", request_path)];

    let result = l402_access_handler(auth_header, uri, method, amount_msat, caveats.clone());
    
    // Only set L402 header if result is 402
    if result == 402 {
        let module = unsafe { MODULE.as_ref().expect("Module not initialized") };
        
        // Use a lazily initialized static runtime
        static RUNTIME: OnceLock<Runtime> = OnceLock::new();
        let rt = RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread() // Use single-threaded runtime for less overhead
                .enable_all()
                .build()
                .expect("tokio runtime init")
        });
        
        // Use block_on as getting better performance than spawn + channel
        let header_result = rt.block_on(async {
            module.get_l402_header(caveats.clone(), amount_msat).await
        });
        
        match header_result {
            Some(header_value) => {
                unsafe {
                    ngx_log_error!(NGX_LOG_INFO, log_ref, "Setting L402 header");
                    let req = Request::from_ngx_http_request(request);
                    req.add_header_out("WWW-Authenticate", &header_value);
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

pub fn l402_access_handler(auth_header: Option<String>, uri: String, method: u32, amount_msat: i64, caveats: Vec<String>) -> isize {
    let module = unsafe {
        MODULE.as_ref().expect("Module not initialized")
    };

    println!("Processing request - Method: {:?}, URI: {:?}", method, uri);
    
    if let Some(auth_str) = auth_header {
        println!("Found authorization header");
        println!("Authorization: {}", auth_str);

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
            
            let verify_result = rt.block_on(async {
                module.verify_cashu_token(&token, amount_msat).await
            });
            
            match verify_result {
                Ok(true) => {
                    return NGX_DECLINED.try_into().unwrap();
                },
                Ok(false) => {
                    eprintln!("Cashu token verification failed");
                    return 401;
                },
                Err(e) => {
                    eprintln!("Error verifying Cashu token: {:?}", e);
                    return 401;
                }
            }
        } else {
            match utils::parse_l402_header(&auth_str) {
                Ok((mac, preimage)) => {
                    match l402::verify_l402(&mac, caveats.clone(), module.middleware.root_key.clone(), preimage) {
                        Ok(_) => {
                            println!("L402 verification successful");
                            return NGX_DECLINED.try_into().unwrap();
                        },
                        Err(e) => {
                            eprintln!("L402 verification failed: {:?}", e);
                            return 401;
                        }
                    }
                },
                Err(e) => {
                    println!("Failed to parse L402 header: {:?}", e);
                    return 401;
                }
            }
        }
    }

    println!("No authorization header found, sending L402 challenge");
    402
}

pub unsafe extern "C" fn init_module(cycle: *mut ngx_cycle_s) -> isize {
    println!("Starting module initialization");

    let log = (*cycle).log;
    
    ngx_log_error!(NGX_LOG_INFO, log, "Starting module initialization");
    
    if cycle.is_null() {
        println!("Error: Cycle pointer is null");
        return -1;
    }

    // Check if Cashu eCash support is enabled
    let cashu_ecash_support_var = std::env::var("CASHU_ECASH_SUPPORT").unwrap_or_else(|_| "false".to_string());
    let cashu_ecash_support = cashu_ecash_support_var.trim().to_lowercase() == "true";
    
    if cashu_ecash_support {
        println!("Cashu eCash support is enabled");

        // Initialize Cashu database
        let db_path = std::env::var("CASHU_DB_PATH").unwrap_or_else(|_| "/var/lib/nginx/cashu_wallet.redb".to_string());
        ngx_log_error!(NGX_LOG_INFO, log, "CASHU_DB_PATH: '{}'", db_path);

        match cashu::initialize_cashu(&db_path) {
            Ok(_) => {
                ngx_log_error!(NGX_LOG_INFO, log, "Cashu database initialized successfully");
            },
            Err(e) => {
                ngx_log_error!(NGX_LOG_ERR, log, "Failed to initialize Cashu: {}", e);
            }
        }
    } else {
        println!("Cashu eCash support is disabled");
    }

    INIT.call_once(|| {
        println!("Initializing runtime and L402Module");
        match std::panic::catch_unwind(|| {
            let rt = Runtime::new().expect("Failed to create runtime");
            let module = rt.block_on(async {
                L402Module::new().await
            });
            
            unsafe {
                MODULE = Some(module);
            }
            println!("L402Module initialized successfully");
        }) {
            Ok(_) => (),
            Err(e) => {
                println!("Panic during initialization: {:?}", e);
                unsafe {
                    MODULE = None;
                }
            }
        }
    });

    println!("Module initialization complete");

    let redeem_on_lightning = std::env::var("CASHU_REDEEM_ON_LIGHTNING")
        .unwrap_or_else(|_| "false".to_string())
        .trim()
        .to_lowercase() == "true";

    if redeem_on_lightning && cashu_ecash_support {
        ngx_log_error!(NGX_LOG_INFO, log, "Automatic Cashu redemption enabled");

        // Get redemption interval
        let interval_secs = std::env::var("CASHU_REDEMPTION_INTERVAL_SECS")
            .unwrap_or_else(|_| "3600".to_string()) // Default 1 hour
            .parse::<u64>()
            .unwrap_or(3600);

        let module = unsafe { MODULE.as_ref().expect("Module not initialized") };
        let ln_client = module.middleware.ln_client.clone();

        // Spawn redemption task in a separate thread to avoid blocking nginx
        let _ =std::thread::Builder::new()
            .name("cashu_redemption".into())
            .spawn(move || {
                println!("Starting redemption task");
                
                // Create a new runtime for this thread
                let thread_rt = Runtime::new().expect("Failed to create thread runtime");
                
                thread_rt.block_on(async move {
                    loop {
                        let ln_client_conn = lnclient::LNClientConn {
                            ln_client: ln_client.clone(),
                        };

                        match cashu::redeem_to_lightning(&ln_client_conn).await {
                            Ok(true) => println!("Successfully redeemed Cashu tokens"),
                            Ok(false) => println!("No tokens to redeem"), 
                            Err(e) => eprintln!("Error redeeming tokens: {}", e)
                        }

                        println!("Sleeping for {} seconds", interval_secs);
                        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
                    }
                });
            });
    }
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

pub unsafe extern "C" fn ngx_http_l402_amount_set(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let args = (*(*cf).args).elts as *mut ngx_str_t;

        let val = (*args.add(1)).to_str();

        match val.parse::<i64>() {
            Ok(amount) if amount > 0 => {
                conf.amount_msat = amount;
                println!("Set L402 amount_msat to {}", amount);
            },
            _ => {
                println!("Invalid amount_msat value: {}", val);
                return std::ptr::null_mut();
            }
        }
    };

    std::ptr::null_mut()
}
