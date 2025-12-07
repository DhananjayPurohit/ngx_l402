use crate::cashu_redemption_logger;
use cdk;
use cdk::mint_url::MintUrl;
use l402_middleware::lnclient;
use redis;
use log::{debug, error, info, warn};
use std::cell::RefCell;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;
use tonic_openssl_lnd::lnrpc;

// Thread-local storage to track processed tokens
thread_local! {
    static PROCESSED_TOKENS: RefCell<Option<HashSet<String>>> = RefCell::new(None);
}

const MSAT_PER_SAT: u64 = 1000;

// Database singleton using cdk-sqlite
static CASHU_DB: OnceLock<Arc<cdk_sqlite::WalletSqliteDatabase>> = OnceLock::new();

// Redis client for token mappings
static REDIS_CLIENT: OnceLock<Arc<redis::Client>> = OnceLock::new();

// Whitelisted mints singleton
static WHITELISTED_MINTS: OnceLock<HashSet<String>> = OnceLock::new();

// P2PK mode flag and keys
static P2PK_MODE_ENABLED: OnceLock<bool> = OnceLock::new();
static P2PK_PRIVATE_KEY: OnceLock<String> = OnceLock::new();
static P2PK_PUBLIC_KEY: OnceLock<String> = OnceLock::new();

// Cashu eCash support flag
static CASHU_ECASH_ENABLED: OnceLock<bool> = OnceLock::new();

pub fn is_p2pk_mode_enabled() -> bool {
    P2PK_MODE_ENABLED.get().copied().unwrap_or(false)
}

pub fn is_cashu_ecash_enabled() -> bool {
    CASHU_ECASH_ENABLED.get().copied().unwrap_or(false)
}

fn initialize_redis_client() -> Result<(), String> {
    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(redis_url.as_str())
        .map_err(|e| format!("Failed to create Redis client: {}", e))?;

    let _ = REDIS_CLIENT.set(Arc::new(client));
    info!("✅ Redis client initialized for token mappings");
    Ok(())
}

pub fn initialize_cashu(db_url: &str) -> Result<(), String> {
    // Initialize PROCESSED_TOKENS with empty HashSet
    PROCESSED_TOKENS.with(|tokens| {
        *tokens.borrow_mut() = Some(HashSet::new());
    });

    // Set Cashu eCash enabled flag
    let _ = CASHU_ECASH_ENABLED.set(true);

    // Create runtime for async initialization
    let rt = Runtime::new().expect("Failed to create runtime");

    // Initialize SQLite database with WAL mode and redis
    rt.block_on(async {
        match cdk_sqlite::WalletSqliteDatabase::new(db_url).await {
            Ok(db) => {
                info!("✅ Cashu SQLite database initialized successfully with WAL mode");
                let _ = CASHU_DB.set(Arc::new(db));

                initialize_redis_client()?;

                Ok(())
            }
            Err(e) => {
                let error = format!("Failed to create Cashu SQLite database: {:?}", e);
                error!("❌ {}", error);
                Err(error)
            }
        }
    })
}

pub fn initialize_whitelisted_mints(whitelisted_mints_str: &str) -> Result<(), String> {
    if whitelisted_mints_str.trim().is_empty() {
        info!("ℹ️ Empty whitelisted mints string provided");
        return Ok(());
    }

    let mut whitelisted_set = HashSet::new();

    // Split by comma and trim each mint URL
    for mint_url in whitelisted_mints_str.split(',') {
        let trimmed_mint = mint_url.trim();
        if !trimmed_mint.is_empty() {
            whitelisted_set.insert(trimmed_mint.to_string());
            info!("✅ Added whitelisted mint: {}", trimmed_mint);
        }
    }

    if whitelisted_set.is_empty() {
        return Err("No valid mint URLs found in whitelisted mints".to_string());
    }

    match WHITELISTED_MINTS.set(whitelisted_set) {
        Ok(_) => {
            info!("✅ Whitelisted mints initialized successfully");
            Ok(())
        }
        Err(_) => Err("Failed to set whitelisted mints - already initialized".to_string()),
    }
}

pub fn is_mint_whitelisted(mint_url: &str) -> bool {
    // If no whitelisted mints are configured, allow all mints
    if let Some(whitelisted_mints) = WHITELISTED_MINTS.get() {
        whitelisted_mints.contains(mint_url)
    } else {
        info!("ℹ️ No whitelisted mints configured - allowing all mints");
        true
    }
}

pub fn get_whitelisted_mints() -> Option<&'static HashSet<String>> {
    WHITELISTED_MINTS.get()
}

// Store mapping between token hash and LNURL address
fn store_token_mapping(token: &str, route_lnurl: Option<String>) -> Result<(), String> {
    let client = REDIS_CLIENT.get()
        .ok_or("Redis client not initialized")?;

    // Use route-specific or global LNURL address
    let lnurl = route_lnurl.unwrap_or_else(|| {
        std::env::var("LNURL_ADDRESS").unwrap_or_default()
    });

    if lnurl.is_empty() {
        return Err("No LNURL address available for token mapping".to_string());
    }

    let token_hash = Hasher::new()
        .update(token.as_bytes())
        .finalize()
        .to_hex();

    // Store with 7-day TTL
    let mut conn = client.get_connection()
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    redis::cmd("SETEX")
        .arg(format!("token_mapping:{}", &token_hash[..16]))
        .arg(7 * 24 * 60 * 60)
        .arg(&lnurl)
        .query(&mut conn)
        .map_err(|e| format!("Failed to store token mapping in Redis: {}", e))?;

    info!("Stored token mapping: {} -> {}", &token_hash[..16], &lnurl);
    Ok(())
}


/// Initialize P2PK mode if enabled
pub fn initialize_p2pk_mode() -> Result<(), String> {
    let p2pk_mode = std::env::var("CASHU_P2PK_MODE")
        .unwrap_or_else(|_| "false".to_string())
        .trim()
        .to_lowercase()
        == "true";

    if !p2pk_mode {
        info!("ℹ️ P2PK mode is disabled");
        let _ = P2PK_MODE_ENABLED.set(false);
        return Ok(());
    }

    info!("🔐 P2PK mode is enabled");

    // Verify CASHU_WHITELISTED_MINTS is set (required for P2PK mode)
    if get_whitelisted_mints().is_none() {
        return Err("P2PK mode requires CASHU_WHITELISTED_MINTS to be configured".to_string());
    }

    // Get private key from environment
    let private_key_hex = std::env::var("CASHU_P2PK_PRIVATE_KEY")
        .map_err(|_| "CASHU_P2PK_PRIVATE_KEY not set but P2PK mode is enabled".to_string())?;

    if private_key_hex.trim().is_empty() {
        return Err("CASHU_P2PK_PRIVATE_KEY is empty".to_string());
    }

    // Use the cdk SecretKey to derive public key
    let private_key = cdk::nuts::SecretKey::from_hex(&private_key_hex)
        .map_err(|e| format!("Invalid private key hex: {:?}", e))?;

    // Derive public key from private key
    let public_key = private_key.public_key();

    info!("🔑 P2PK public key: {}", public_key);

    // Store keys as hex strings for later use
    P2PK_PRIVATE_KEY
        .set(private_key_hex)
        .map_err(|_| "Failed to set private key".to_string())?;
    P2PK_PUBLIC_KEY
        .set(public_key.to_string())
        .map_err(|_| "Failed to set public key".to_string())?;

    let _ = P2PK_MODE_ENABLED.set(true);
    info!("✅ P2PK mode initialized with public key");

    Ok(())
}

/// Generate NUT-18/NUT-24 payment request for X-Cashu header
pub fn generate_payment_request(
    amount_msat: i64,
    whitelisted_mints: &HashSet<String>,
) -> Result<String, String> {
    let public_key_str = P2PK_PUBLIC_KEY
        .get()
        .ok_or("P2PK public key not initialized")?;

    let mints_array: Vec<String> = whitelisted_mints.iter().cloned().collect();

    // NUT-18/NUT-24 payment request format with NUT-10 P2PK requirement
    let payment_request = serde_json::json!({
        "a": amount_msat / 1000, // Convert to sats
        "u": "sat",
        "m": mints_array,
        "t": [], // Empty transport array = in-band transport (X-Cashu header)
        "nut10": {
            "k": "P2PK",           // NUT-10 secret kind
            "d": public_key_str    // NUT-10 secret data - our public key!
        }
    });

    info!(
        "📤 NUT-18 payment request generated with P2PK pubkey: {}",
        public_key_str
    );
    debug!("📋 Payment request: {:?}", payment_request);

    // Encode as NUT-18 format: "creq" + "A" + base64_urlsafe(CBOR(PaymentRequest))
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&payment_request, &mut cbor_bytes)
        .map_err(|e| format!("Failed to encode CBOR: {}", e))?;

    use base64::{engine::general_purpose, Engine as _};
    let base64_encoded = general_purpose::URL_SAFE_NO_PAD.encode(&cbor_bytes);

    // NUT-18 format: prefix + version + encoded data
    let nut18_encoded = format!("creqA{}", base64_encoded);

    info!(
        "✅ NUT-18 encoded payment request: {}",
        &nut18_encoded[..50.min(nut18_encoded.len())]
    );

    Ok(nut18_encoded)
}

pub async fn verify_cashu_token(token: &str, amount_msat: i64, lnurl_address: Option<String>) -> Result<bool, String> {
    // Log database status
    debug!("🔍 Verifying Cashu token, checking database connection...");

    // Check if token was already processed
    let token_already_processed = PROCESSED_TOKENS.with(|tokens| {
        if let Some(set) = tokens.borrow().as_ref() {
            set.contains(token)
        } else {
            false
        }
    });

    if token_already_processed {
        debug!("✅ Cashu token already processed");
        return Ok(true);
    }

    // Decode the token from string
    let token_decoded = match cdk::nuts::Token::from_str(token) {
        Ok(token) => token,
        Err(e) => {
            error!("❌ Failed to decode Cashu token: {}", e);
            return Err(format!("Failed to decode Cashu token: {}", e));
        }
    };

    // Calculate total token amount in millisatoshis
    let total_amount = token_decoded
        .value()
        .map_err(|e| format!("Failed to get token value: {}", e))?;

    // Check if the token unit is in millisatoshis or satoshis
    let total_amount_msat: u64 = if token_decoded.unit().unwrap() == cdk::nuts::CurrencyUnit::Sat {
        u64::from(total_amount) * MSAT_PER_SAT
    } else if token_decoded.unit().unwrap() == cdk::nuts::CurrencyUnit::Msat {
        u64::from(total_amount)
    } else {
        // Other units not supported
        return Err(format!(
            "Unsupported token unit: {:?}",
            token_decoded.unit().unwrap()
        ));
    };

    // Check if the token amount is sufficient
    if total_amount_msat < amount_msat as u64 {
        warn!(
            "⚠️ Cashu token amount insufficient: {} msat (required: {} msat)",
            total_amount_msat, amount_msat
        );
        return Ok(false);
    }

    info!(
        "✅ Successfully decoded Cashu token with {} msat (required: {} msat)",
        total_amount_msat, amount_msat
    );

    // Extract mint URL from the token
    let mint_url = token_decoded
        .mint_url()
        .map_err(|e| format!("Failed to get mint URL: {}", e))?;

    // Check if the mint is whitelisted
    if !is_mint_whitelisted(&mint_url.to_string()) {
        info!("⚠️ Cashu token from non-whitelisted mint: {}", mint_url);
        return Ok(false);
    }

    info!("✅ Cashu token from whitelisted mint: {}", mint_url);

    let unit = token_decoded.unit().unwrap();

    // Use the shared database instance
    let db = CASHU_DB
        .get()
        .ok_or_else(|| "Cashu database not initialized".to_string())?
        .clone();

    // Use seed from environment variable (CASHU_WALLET_SECRET)
    let wallet_secret = std::env::var("CASHU_WALLET_SECRET").unwrap_or_else(|_| {
        warn!("⚠️ CASHU_WALLET_SECRET not set! Using insecure default. Set this in production!");
        "CHANGE_THIS_SECRET_IN_PRODUCTION".to_string()
    });
    let seed_hash = blake3::hash(wallet_secret.as_bytes());
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(seed_hash.as_bytes());
    debug!("🔑 Using seed for receiving token from mint {}", mint_url);

    // Create wallet directly for this specific mint
    let wallet = cdk::wallet::Wallet::new(&mint_url.to_string(), unit, db.clone(), seed, None)
        .map_err(|e| format!("Failed to create wallet: {}", e))?;

    match wallet
        .receive(token, cdk::wallet::ReceiveOptions::default())
        .await
    {
        Ok(_) => {
            info!(
                "✅ Cashu token received successfully from mint: {}",
                mint_url
            );

            // Store the token mapping for redemption with correct LNURL
            if let Err(e) = store_token_mapping(token, lnurl_address) {
                warn!("⚠️ Failed to store token mapping: {}", e);
            }

            // Add token to processed set after successful receive
            PROCESSED_TOKENS.with(|tokens| {
                if let Some(set) = tokens.borrow_mut().as_mut() {
                    set.insert(token.to_string());
                }
            });
            Ok(true)
        }
        Err(e) => {
            error!(
                "❌ Cashu token receive failed from mint {}: {}",
                mint_url, e
            );
            Ok(false)
        }
    }
}

/// Verify Cashu token using P2PK optimized mode (NUT-24)
/// Stores proofs directly in CDK database using cached keysets - no mint swap call
pub async fn verify_cashu_token_p2pk(token: &str, amount_msat: i64, lnurl_address: Option<String>) -> Result<bool, String> {
    info!("🔐 P2PK mode: Optimized token verification");

    // Check memory cache first
    let token_seen = PROCESSED_TOKENS.with(|tokens| {
        tokens
            .borrow()
            .as_ref()
            .map_or(false, |set| set.contains(token))
    });

    if token_seen {
        info!("✅ Token already accepted (cache hit)");
        return Ok(true);
    }

    // Decode and validate token
    let token_decoded =
        cdk::nuts::Token::from_str(token).map_err(|e| format!("Failed to decode token: {}", e))?;

    let mint_url = token_decoded
        .mint_url()
        .map_err(|e| format!("Failed to get mint URL: {}", e))?;

    // Verify mint is whitelisted
    let whitelisted_mints = get_whitelisted_mints().ok_or("No whitelisted mints configured")?;

    if !whitelisted_mints.contains(&mint_url.to_string()) {
        return Err(format!("Mint {} not whitelisted", mint_url));
    }

    // Verify amount
    let total_amount = token_decoded
        .value()
        .map_err(|e| format!("Failed to get value: {}", e))?;

    let total_amount_msat: u64 = if token_decoded.unit().unwrap() == cdk::nuts::CurrencyUnit::Sat {
        u64::from(total_amount) * MSAT_PER_SAT
    } else if token_decoded.unit().unwrap() == cdk::nuts::CurrencyUnit::Msat {
        u64::from(total_amount)
    } else {
        return Err(format!(
            "Unsupported unit: {:?}",
            token_decoded.unit().unwrap()
        ));
    };

    if total_amount_msat < amount_msat as u64 {
        return Err(format!(
            "Insufficient amount: {} < {}",
            total_amount_msat, amount_msat
        ));
    }

    info!("✅ Validated: {} msat from {}", total_amount_msat, mint_url);

    // Setup wallet
    let db = CASHU_DB.get().ok_or("Database not initialized")?.clone();

    let unit = token_decoded.unit().unwrap();
    let wallet_secret = std::env::var("CASHU_WALLET_SECRET")
        .unwrap_or_else(|_| "CHANGE_THIS_SECRET_IN_PRODUCTION".to_string());
    let seed_hash = blake3::hash(wallet_secret.as_bytes());
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(seed_hash.as_bytes());

    let wallet = cdk::wallet::Wallet::new(&mint_url.to_string(), unit.clone(), db, seed, None)
        .map_err(|e| format!("Failed to create wallet: {}", e))?;

    // Get keysets (use cached if available, fetch once if not)
    let keysets_info = match wallet.get_mint_keysets().await {
        Ok(keysets) => {
            debug!("Using cached keysets");
            keysets
        }
        Err(_) => {
            info!("📡 Fetching keysets (one-time per mint)");
            wallet
                .load_mint_keysets()
                .await
                .map_err(|e| format!("Failed to load keysets: {}", e))?
        }
    };

    // Extract proofs using keysets
    let proofs = token_decoded
        .proofs(&keysets_info)
        .map_err(|e| format!("Failed to extract proofs: {}", e))?;

    // Get our keys for P2PK verification
    let private_key_hex = P2PK_PRIVATE_KEY
        .get()
        .ok_or("P2PK private key not initialized")?;
    let public_key_str = P2PK_PUBLIC_KEY
        .get()
        .ok_or("P2PK public key not initialized")?;

    // Reconstruct keys from hex strings
    let private_key = cdk::nuts::SecretKey::from_hex(private_key_hex)
        .map_err(|e| format!("Failed to parse private key: {:?}", e))?;
    let public_key = cdk::nuts::PublicKey::from_hex(public_key_str)
        .map_err(|e| format!("Failed to parse public key: {:?}", e))?;

    // Create spending condition with our public key
    let spending_condition = cdk::nuts::SpendingConditions::new_p2pk(public_key, None);

    // Verify token is P2PK-locked to our public key
    info!("🔓 Verifying token is P2PK-locked to our public key...");
    wallet
        .verify_token_p2pk(&token_decoded, spending_condition.clone())
        .await
        .map_err(|e| format!("Token not locked to our public key: {:?}", e))?;

    info!("✅ Token verified as P2PK-locked to our public key");

    // IMPORTANT: receive_proofs() calls the mint to swap proofs (post_swap), which we want to avoid!
    // Instead, we store the P2PK-locked proofs directly in the database as UNSPENT
    // without swapping them. They can be spent later using our private key.

    use cdk::cdk_database::WalletDatabase;
    use cdk::nuts::State;
    use cdk::types::ProofInfo;

    // Create ProofInfo objects for direct database storage
    let proof_infos: Vec<ProofInfo> = proofs
        .iter()
        .map(|proof| ProofInfo {
            proof: proof.clone(),
            y: proof.y().unwrap(),
            mint_url: mint_url.clone(),
            state: State::Unspent,
            unit: unit.clone(),
            spending_condition: Some(spending_condition.clone()),
        })
        .collect();

    info!(
        "💾 Storing {} P2PK-locked proofs directly in database (NO swap call)",
        proof_infos.len()
    );

    // Store directly in database using update_proofs (same as receive_proofs does internally)
    // Pass empty vec for second parameter (no proofs to delete)
    wallet
        .localstore
        .update_proofs(proof_infos, vec![])
        .await
        .map_err(|e| format!("Failed to store proofs in database: {:?}", e))?;

    // Mark as accepted in memory cache
    PROCESSED_TOKENS.with(|tokens| {
        if let Some(set) = tokens.borrow_mut().as_mut() {
            set.insert(token.to_string());
        }
    });

    // Store the token mapping for redemption with correct LNURL
    if let Err(e) = store_token_mapping(token, lnurl_address) {
        warn!("⚠️ Failed to store token mapping: {}", e);
    }

    info!(
        "✅ ACCEPTED ({} msat stored in CDK database)",
        total_amount_msat
    );

    Ok(true)
}

pub async fn redeem_to_lightning(ln_client_conn: &lnclient::LNClientConn) -> Result<bool, String> {
    cashu_redemption_logger::log_redemption("🚀 Starting smart Cashu token redemption process...");
    info!("🚀 Starting smart Cashu token redemption process...");

    // Get database
    let db = CASHU_DB
        .get()
        .ok_or_else(|| "Cashu database not initialized".to_string())?
        .clone();

    // Get Redis client
    let redis_client = REDIS_CLIENT.get()
        .ok_or("Redis client not initialized")?;

    // Use whitelisted mints for redemption check
    // If no whitelisted mints are configured, we can't redeem
    let whitelisted_mints = WHITELISTED_MINTS
        .get()
        .ok_or_else(|| "No whitelisted mints configured".to_string())?;

    let msg = format!(
        "📊 Checking {} whitelisted mints for tokens: {:?}",
        whitelisted_mints.len(),
        whitelisted_mints.iter().collect::<Vec<_>>()
    );
    cashu_redemption_logger::log_redemption(&msg);
    info!("{}", msg);

    // Use seed from environment variable (must match token verification)
    let wallet_secret = std::env::var("CASHU_WALLET_SECRET").unwrap_or_else(|_| {
        warn!("⚠️ CASHU_WALLET_SECRET not set! Using insecure default. Set this in production!");
        "CHANGE_THIS_SECRET_IN_PRODUCTION".to_string()
    });
    let seed_hash = blake3::hash(wallet_secret.as_bytes());
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(seed_hash.as_bytes());

    // Get configurable parameters from environment
    let min_balance_sats = std::env::var("CASHU_MELT_MIN_BALANCE_SATS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10); // Default to 10 sats if not configured
    let minimum_for_redemption_msat = min_balance_sats * MSAT_PER_SAT;

    let fee_reserve_percent = std::env::var("CASHU_MELT_FEE_RESERVE_PERCENT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0); // Default to 1% fee reserve

    let min_fee_reserve_sats = std::env::var("CASHU_MELT_MIN_FEE_RESERVE_SATS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(4); // Default to 4 sats minimum fee reserve
    let min_fee_reserve_msat = min_fee_reserve_sats * MSAT_PER_SAT;

    let max_proofs_per_melt = std::env::var("CASHU_MAX_PROOFS_PER_MELT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0); // Default to 0 (no limit)

    let msg = if max_proofs_per_melt > 0 {
        format!("⚙️ Melt config: min_balance={} sats, fee_reserve={}%, min_fee_reserve={} sats, max_proofs_per_melt={}", 
            min_balance_sats, fee_reserve_percent, min_fee_reserve_sats, max_proofs_per_melt)
    } else {
        format!("⚙️ Melt config: min_balance={} sats, fee_reserve={}%, min_fee_reserve={} sats, max_proofs_per_melt=unlimited", 
            min_balance_sats, fee_reserve_percent, min_fee_reserve_sats)
    };
    info!("{}", msg);
    cashu_redemption_logger::log_redemption(&msg);

    let mut total_redeemed = 0;
    let mut total_amount_redeemed_msat = 0;
    let mut total_fees_paid_msat = 0;

    // Group tokens by LNURL address for multi-tenant redemption
    // First, get all unspent proofs and their associated LNURL addresses
    let mut proofs_by_lnurl: std::collections::HashMap<String, Vec<(cdk::nuts::Proof, String)>> = std::collections::HashMap::new();

    for mint_url_str in whitelisted_mints.iter() {
        // Validate mint URL format
        if MintUrl::from_str(mint_url_str).is_err() {
            warn!("⚠️ Invalid mint URL format: {}", mint_url_str);
            continue;
        }

        // Create wallet for this mint
        let wallet = match cdk::wallet::Wallet::new(
            mint_url_str,
            cdk::nuts::CurrencyUnit::Sat,
            db.clone(),
            seed,
            None,
        ) {
            Ok(w) => w,
            Err(e) => {
                warn!("⚠️ Failed to create wallet for {}: {}", mint_url_str, e);
                continue;
            }
        };

        let wallet_clone = wallet.clone();

        // Get all spendable proofs
        let proofs = match wallet_clone.get_unspent_proofs().await {
            Ok(p) => p,
            Err(e) => {
                let msg = format!(
                    "❌ Failed to get spendable proofs for {}: {}",
                    wallet.mint_url, e
                );
                error!("{}", msg);
                cashu_redemption_logger::log_redemption(&msg);
                continue;
            }
        };

        if proofs.is_empty() {
            debug!("ℹ️ No spendable proofs found for mint {}", wallet.mint_url);
            continue;
        }

        // Group proofs by their LNURL address using token mapping
        let global_lnurl = std::env::var("LNURL_ADDRESS").unwrap_or_default();

        for proof in proofs {
            // Create a token identifier using proof's Y value and mint URL
            let proof_y = proof.y().unwrap_or_default();
            let token_identifier = format!("{}:{}", wallet.mint_url, proof_y);

            // Hash to match what we stored during verification
            let token_hash = Hasher::new()
                .update(token_identifier.as_bytes())
                .finalize()
                .to_hex();

            // Get Redis connection for this proof
            let mut conn = redis_client.get_connection()
                .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

            // Look up LNURL address for this token
            let lnurl: String = redis::cmd("GET")
                .arg(format!("token_mapping:{}", token_hash))
                .query(&mut conn)
                .unwrap_or_else(|_| global_lnurl.clone());

            if !lnurl.is_empty() {
                proofs_by_lnurl.entry(lnurl).or_insert_with(Vec::new).push((proof, wallet.mint_url.clone()));
            }
        }
    }

    // Now process each LNURL group
    for (lnurl_address, proofs_with_mint) in proofs_by_lnurl {
        info!("Processing {} proofs for LNURL: {}", proofs_with_mint.len(), lnurl_address);

        // Calculate total amount for this LNURL group
        let total_amount: u64 = proofs_with_mint
            .iter()
            .map(|(p, _)| p.amount.into() * MSAT_PER_SAT)
            .sum();

        if total_amount == 0 {
            debug!("Total amount is 0 for LNURL {}", lnurl_address);
            continue;
        }

        let total_amount_sats = total_amount / MSAT_PER_SAT;

        let msg = format!(
            "💰 Found {} proofs with total value {} sats for LNURL {}",
            proofs_with_mint.len(), total_amount_sats, lnurl_address
        );
        info!("{}", msg);
        cashu_redemption_logger::log_redemption(&msg);

        // Check minimum balance threshold
        if total_amount < minimum_for_redemption_msat {
            let msg = format!(
                "⏳ Skipping redemption for LNURL {} - balance {} msat is below minimum {} msat",
                lnurl_address, total_amount, minimum_for_redemption_msat
            );
            info!("{}", msg);
            cashu_redemption_logger::log_redemption(&msg);
            continue;
        }

        // Calculate fee reserve based on percentage with minimum fallback
        let percentage_fee_msat =
            ((total_amount as f64) * (fee_reserve_percent / 100.0)) as u64;
        let fee_reserve_msat = percentage_fee_msat.max(min_fee_reserve_msat);

        let msg = format!("💰 Fee calculation: {} msat total * {}% = {} msat, using max({}, {}) = {} msat reserve",
            total_amount, fee_reserve_percent, percentage_fee_msat,
            percentage_fee_msat, min_fee_reserve_msat, fee_reserve_msat);
        info!("{}", msg);
        cashu_redemption_logger::log_redemption(&msg);

        // Ensure we have enough after fee reserve
        if total_amount <= fee_reserve_msat {
            let msg = format!(
                "⚠️ Insufficient balance after fee reserve: {} msat total <= {} msat fees",
                total_amount, fee_reserve_msat
            );
            warn!("{}", msg);
            cashu_redemption_logger::log_redemption(&msg);
            continue;
        }

        // Select proofs to melt based on configured limit
        let (proofs_to_melt, selected_total_msat) =
            if max_proofs_per_melt > 0 && proofs_with_mint.len() > max_proofs_per_melt {
                // Limit exceeded - select only the configured number of proofs
                let selected_proofs: Vec<_> =
                    proofs_with_mint.iter().take(max_proofs_per_melt).cloned().collect();

                // Calculate total value of selected proofs
                let selected_total: u64 = selected_proofs
                    .iter()
                    .map(|(p, _)| p.amount.into() * MSAT_PER_SAT)
                    .sum();

                let msg = format!(
                    "⚠️ Have {} proofs (>{} limit) - selecting first {} proofs worth {} sats",
                    proofs_with_mint.len(),
                    max_proofs_per_melt,
                    selected_proofs.len(),
                    selected_total / MSAT_PER_SAT
                );
                info!("{}", msg);
                cashu_redemption_logger::log_redemption(&msg);

                (selected_proofs, selected_total)
            } else {
                // No limit or under limit - use all proofs
                (proofs_with_mint.clone(), total_amount)
            };

        // Calculate fee reserve based on selected proofs
        let percentage_fee_selected =
            ((selected_total_msat as f64) * (fee_reserve_percent / 100.0)) as u64;
        let fee_reserve_selected_msat = percentage_fee_selected.max(min_fee_reserve_msat);
        let redeemable_amount_msat = selected_total_msat - fee_reserve_selected_msat;

        // Create LNURL client for this specific address
        let lnurl_config = lnurl::LNURLOptions {
            address: lnurl_address.clone(),
        };

        let ln_client_config = lnclient::LNClientConfig {
            ln_client_type: "LNURL".to_string(),
            lnd_config: None,
            lnurl_config: Some(lnurl_config),
            nwc_config: None,
            cln_config: None,
            root_key: std::env::var("ROOT_KEY")
                .unwrap_or_else(|_| "root_key".to_string())
                .as_bytes()
                .to_vec(),
        };

        let ln_client = match lnclient::LNClientConn::new(ln_client_config).await {
            Ok(client) => client,
            Err(e) => {
                let msg = format!(
                    "❌ Failed to create LNURL client for {}: {}",
                    lnurl_address, e
                );
                error!("{}", msg);
                cashu_redemption_logger::log_redemption(&msg);
                continue;
            }
        };

        // Generate Lightning invoice for the redeemable amount
        let memo = format!(
            "Redeeming {} proofs from multiple mints to {}",
            proofs_to_melt.len(),
            lnurl_address
        );

        // Group proofs by mint for melting
        let mut proofs_by_mint: std::collections::HashMap<String, Vec<cdk::nuts::Proof>> = std::collections::HashMap::new();
        for (proof, mint_url) in proofs_to_melt {
            proofs_by_mint.entry(mint_url).or_insert_with(Vec::new).push(proof);
        }

        let (invoice, _payment_hash) = match ln_client
            .generate_invoice(lnrpc::Invoice {
                value_msat: redeemable_amount_msat as i64,
                memo: memo.clone(),
                ..Default::default()
            })
            .await
        {
            Ok((invoice, payment_hash)) => {
                cashu_redemption_logger::log_redemption(&format!(
                    "✅ Generated invoice for {}: payment_hash={}",
                    lnurl_address, payment_hash
                ));
                (invoice, payment_hash)
            }
            Err(e) => {
                let msg = format!(
                    "❌ Failed to generate invoice for {}: {}",
                    lnurl_address, e
                );
                error!("{}", msg);
                cashu_redemption_logger::log_redemption(&msg);
                continue;
            }
        };

        
        // Process each mint's proofs
        for (mint_url_str, mint_proofs) in proofs_by_mint {
            // Create wallet for this mint
            let wallet = match cdk::wallet::Wallet::new(
                mint_url_str,
                cdk::nuts::CurrencyUnit::Sat,
                db.clone(),
                seed,
                None,
            ) {
                Ok(w) => w,
                Err(e) => {
                    warn!("⚠️ Failed to create wallet for {}: {}", mint_url_str, e);
                    continue;
                }
            };

            // Get melt quote
            let quote = match wallet.melt_quote(invoice.clone(), None).await {
                Ok(q) => {
                    let actual_fee_reserve_sats: u64 = q.fee_reserve.into();
                    let actual_fee_reserve_msat = actual_fee_reserve_sats * MSAT_PER_SAT;

                    if actual_fee_reserve_msat > fee_reserve_selected_msat {
                        let msg = format!("⚠️ Actual fees ({} msat) higher than reserve ({} msat)",
                            actual_fee_reserve_msat, fee_reserve_selected_msat);
                        warn!("{}", msg);
                    }
                    q
                }
                Err(e) => {
                    let msg = format!(
                        "❌ Failed to create melt quote for {}: {}",
                        mint_url_str, e
                    );
                    error!("{}", msg);
                    cashu_redemption_logger::log_redemption(&msg);
                    continue;
                }
            };

            // Melt the proofs
            let melt_result = if is_p2pk_mode_enabled() {
                if let Some(private_key_hex) = P2PK_PRIVATE_KEY.get() {
                    if let Ok(private_key) = cdk::nuts::SecretKey::from_hex(private_key_hex) {
                        info!("🔓 Melting {} P2PK-locked proofs", mint_proofs.len());

                        // Sign the selected proofs
                        let mut signed_proofs = mint_proofs.clone();
                        for proof in &mut signed_proofs {
                            if let Err(e) = proof.sign_p2pk(private_key.clone()) {
                                error!("❌ Failed to sign proof: {:?}", e);
                            }
                        }

                        wallet.melt_proofs(&quote.id, signed_proofs).await
                    } else {
                        wallet.melt(&quote.id).await
                    }
                } else {
                    wallet.melt(&quote.id).await
                }
            } else {
                wallet.melt(&quote.id).await
            };

            match melt_result {
                Ok(result) => {
                    let actual_fees_sats: u64 = quote.fee_reserve.into();
                    let actual_fees_msat = actual_fees_sats * MSAT_PER_SAT;
                    total_fees_paid_msat += actual_fees_msat;

                    let msg = format!("✅ Successfully redeemed {} proofs from {} to {}: {} msat",
                        mint_proofs.len(), mint_url_str, lnurl_address, redeemable_amount_msat);
                    info!("{}", msg);
                    cashu_redemption_logger::log_redemption(&msg);
                    total_redeemed += mint_proofs.len();
                }
                Err(e) => {
                    let msg = format!("❌ Failed to melt proofs for {}: {}", mint_url_str, e);
                    error!("{}", msg);
                    cashu_redemption_logger::log_redemption(&msg);
                }
            }

        total_amount_redeemed_msat += redeemable_amount_msat;
    }

    let msg = format!(
        "✅ Smart Cashu redemption completed: {} proofs → {} msat to Lightning + {} msat fees",
        total_redeemed, total_amount_redeemed_msat, total_fees_paid_msat
    );
    info!("{}", msg);
    cashu_redemption_logger::log_redemption(&msg);
    Ok(total_redeemed > 0)
}
