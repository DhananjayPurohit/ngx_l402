use crate::cashu_redemption_logger;
use cdk;
use redis::{Commands};
use cdk::mint_url::MintUrl;
use l402_middleware::{lnclient, lnurl};
use log::{debug, error, info, warn};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;
use tonic_openssl_lnd::lnrpc;
use crate::REDIS_CLIENT;
use sha2::{Sha256, Digest};
use hex;

// Thread-local storage to track processed tokens
thread_local! {
    static PROCESSED_TOKENS: RefCell<Option<HashSet<String>>> = RefCell::new(None);
}

const MSAT_PER_SAT: u64 = 1000;

// Database singleton using cdk-sqlite
static CASHU_DB: OnceLock<Arc<cdk_sqlite::WalletSqliteDatabase>> = OnceLock::new();

// Whitelisted mints singleton
static WHITELISTED_MINTS: OnceLock<HashSet<String>> = OnceLock::new();

// P2PK mode flag and keys
static P2PK_MODE_ENABLED: OnceLock<bool> = OnceLock::new();
static P2PK_PRIVATE_KEY: OnceLock<String> = OnceLock::new();
static P2PK_PUBLIC_KEY: OnceLock<String> = OnceLock::new();

// Cashu eCash support flag
static CASHU_ECASH_ENABLED: OnceLock<bool> = OnceLock::new();

// LN Client for non-LNURL redemption (single-tenant mode)
static LN_CLIENT: OnceLock<Arc<tokio::sync::Mutex<dyn lnclient::LNClient + Send>>> = OnceLock::new();
static LN_CLIENT_TYPE: OnceLock<String> = OnceLock::new();

pub fn is_p2pk_mode_enabled() -> bool {
    P2PK_MODE_ENABLED.get().copied().unwrap_or(false)
}

pub fn is_cashu_ecash_enabled() -> bool {
    CASHU_ECASH_ENABLED.get().copied().unwrap_or(false)
}

/// Check if multi-tenant LNURL mode is enabled (LN_CLIENT_TYPE=LNURL)
pub fn is_multi_tenant_enabled() -> bool {
    LN_CLIENT_TYPE.get().map_or(false, |t| t == "LNURL")
}

/// Initialize the LN client for cashu redemption (called from lib.rs)
pub fn initialize_ln_client(
    ln_client: Arc<tokio::sync::Mutex<dyn lnclient::LNClient + Send>>,
    client_type: String,
) -> Result<(), String> {
    LN_CLIENT_TYPE
        .set(client_type.clone())
        .map_err(|_| "LN_CLIENT_TYPE already initialized".to_string())?;

    LN_CLIENT
        .set(ln_client)
        .map_err(|_| "LN_CLIENT already initialized".to_string())?;

    if is_multi_tenant_enabled() {
        info!("🏢 Multi-tenant LNURL mode enabled for Cashu redemption");
    } else {
        info!("🔧 Single-tenant {} mode enabled for Cashu redemption", client_type);
    }

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

    // Initialize SQLite database with WAL mode
    rt.block_on(async {
        match cdk_sqlite::WalletSqliteDatabase::new(db_url).await {
            Ok(db) => {
                info!("✅ Cashu SQLite database initialized successfully with WAL mode");
                let _ = CASHU_DB.set(Arc::new(db));

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

fn get_lnurl_from_proof(proof: &cdk::nuts::Proof) -> Result<Option<String>, String> {
    let client = REDIS_CLIENT.get().ok_or("Redis client is not initialised")?;

    let mut client_guard = client.lock()
        .map_err(|_| "Failed to lock redis client".to_string())?;

    let secret = proof.secret.to_string();

    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());

    let proof_hash = hex::encode(hasher.finalize());

    let redis_key = format!("cashu:proof_lnurl:{}", proof_hash);
    let mut conn = client_guard.get_connection()
        .map_err(|e| format!("Failed to get redis connection: {}", e))?;

    let lnurl: Option<String> = conn.get(&redis_key)
        .map_err(|e| format!("Failed to get proof mapping: {}", e))?;

    Ok(lnurl)
}

fn set_proof_to_lnurl(proofs: cdk::nuts::Proofs, lnurl_route: Option<String>) -> Result<(), String> {
    let client = REDIS_CLIENT.get().ok_or("Redis client is not initialised")?;

    let mut client_guard = client.lock()
        .map_err(|_| "Failed to lock redis client".to_string())?;

    let lnurl = lnurl_route.unwrap_or_else(|| {
        std::env::var("LNURL_ADDRESS").unwrap_or_default()
    });

    if lnurl.is_empty() {
        return Err("No LNURL address available for cashu token".to_string());
    }

    let mut conn = client_guard.get_connection()
        .map_err(|e| format!("Failed to get redis connection: {}", e))?;

    for proof in proofs {
        let secret = proof.secret.to_string();

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());

        let proof_hash = hex::encode(hasher.finalize());

        let redis_key = format!("cashu:proof_lnurl:{}", proof_hash);
        conn.set::<_, _, ()>(&redis_key, &lnurl)
            .map_err(|e| format!("Failed to set proof mapping: {}", e))?;
    }

    Ok(())
}

/// Remove proof-to-lnurl mappings from Redis after proofs have been melted
fn remove_proof_lnurl_mappings(proofs: &cdk::nuts::Proofs) -> Result<(), String> {
    let client = REDIS_CLIENT.get().ok_or("Redis client is not initialised")?;

    let client_guard = client.lock()
        .map_err(|_| "Failed to lock redis client".to_string())?;

    let mut conn = client_guard.get_connection()
        .map_err(|e| format!("Failed to get redis connection: {}", e))?;

    for proof in proofs {
        let secret = proof.secret.to_string();

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());

        let proof_hash = hex::encode(hasher.finalize());

        let redis_key = format!("cashu:proof_lnurl:{}", proof_hash);
        let _: Result<(), _> = conn.del(&redis_key);
    }

    Ok(())
}

{
 cashu:proof_lnurl:p1: lnurl1,
 cashu:proof_lnurl:p2: lnurl2,
}

/// Group proofs by their associated lnurl address for multi-tenant redemption
fn group_proofs_by_lnurl(proofs: cdk::nuts::Proofs) -> HashMap<String, cdk::nuts::Proofs> {
    let mut grouped: HashMap<String, cdk::nuts::Proofs> = HashMap::new();
    let default_lnurl = std::env::var("LNURL_ADDRESS").unwrap_or_else(|| "admin@getalby.com")

    for proof in proofs {
        let lnurl = get_lnurl_from_proof(&proof)
            .ok()
            .flatten()
            .unwrap_or_else(|| default_lnurl.clone());

        if lnurl.is_empty() {
            continue;
        }

        grouped.entry(lnurl).or_insert_with(Vec::new).push(proof);
    }

    grouped
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

pub async fn verify_cashu_token(token: &str, amount_msat: i64, lnurl_addr: Option<String>) -> Result<bool, String> {
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

            if is_multi_tenant_enabled() {
                let proofs = wallet.get_unspent_proofs().await
                .map_err(|e| format!("Failed to get unspent proofs: {}", e))?;
                if let Err(e) = set_proof_to_lnurl(proofs.clone(), lnurl_addr) {
                    warn!("⚠️ Failed to set proof-to-lnurl mapping: {}", e);
                }
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
pub async fn verify_cashu_token_p2pk(token: &str, amount_msat: i64, lnurl_addr: Option<String>) -> Result<bool, String> {
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


    if is_multi_tenant_enabled() {
        if let Err(e) = set_proof_to_lnurl(proofs.clone(), lnurl_addr) {
            warn!("⚠️ Failed to set proof-to-lnurl mapping: {}", e);
        }
    }

    // Mark as accepted in memory cache
    PROCESSED_TOKENS.with(|tokens| {
        if let Some(set) = tokens.borrow_mut().as_mut() {
            set.insert(token.to_string());
        }
    });

    info!(
        "✅ ACCEPTED ({} msat stored in CDK database)",
        total_amount_msat
    );

    Ok(true)
}

pub async fn redeem_to_lightning() -> Result<bool, String> {
    cashu_redemption_logger::log_redemption("🚀 Starting smart Cashu token redemption process...");
    info!("🚀 Starting smart Cashu token redemption process...");

    // Get database
    let db = CASHU_DB
        .get()
        .ok_or_else(|| "Cashu database not initialized".to_string())?
        .clone();

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

    // Process each whitelisted mint
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

        // Calculate total amount
        let total_amount: u64 = wallet_clone.total_balance().await.unwrap().into();

        if total_amount == 0 {
            debug!("ℹ️ Total amount is 0 for mint {}", wallet.mint_url);
            cashu_redemption_logger::log_redemption(&format!(
                "ℹ️ Total amount is 0 for mint {}",
                wallet.mint_url
            ));
            continue;
        }

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
            cashu_redemption_logger::log_redemption(&format!(
                "ℹ️ No spendable proofs found for mint {}",
                wallet.mint_url
            ));
            continue;
        }

        let msg = format!(
            "💰 Found {} proofs for mint {}",
            proofs.len(),
            wallet.mint_url
        );
        info!("{}", msg);
        cashu_redemption_logger::log_redemption(&msg);

        // Check if multi-tenant LNURL mode is enabled. Simply checks if lnclient is lnurl for now
        let is_multi_tenant = is_multi_tenant_enabled();

        // Build proof groups based on mode
        let proof_groups: Vec<(String, cdk::nuts::Proofs)> = if is_multi_tenant {
            // Multi-tenant: group proofs by their lnurl address
            let proofs_by_lnurl = group_proofs_by_lnurl(proofs);
            let msg = format!(
                "Multi-tenant mode: Grouped proofs into {} tenant(s) for mint {}",
                proofs_by_lnurl.len(),
                wallet.mint_url
            );
            info!("{}", msg);
            cashu_redemption_logger::log_redemption(&msg);
            proofs_by_lnurl.into_iter().collect()
        } else {
            // Single-tenant: all proofs go to the configured LN client (LND, CLN, NWC, or LNURL)
            let client_type = LN_CLIENT_TYPE.get().map_or("default", |s| s.as_str());
            let msg = format!(
                "🔧 Single-tenant {} mode: All {} proofs for mint {}",
                client_type,
                proofs.len(),
                wallet.mint_url
            );
            info!("{}", msg);
            cashu_redemption_logger::log_redemption(&msg);
            vec![(client_type.to_string(), proofs)]
        };

        // Process each proof group
        for (client_id, group_proofs) in proof_groups {
            let msg = format!(
                "🔄 Processing {} proofs for client: {}",
                group_proofs.len(),
                client_id
            );
            info!("{}", msg);
            cashu_redemption_logger::log_redemption(&msg);

            // Calculate total amount for this group
            let group_total_msat: u64 = group_proofs
                .iter()
                .map(|p| {
                    let amount: u64 = p.amount.into();
                    if wallet.unit == cdk::nuts::CurrencyUnit::Sat {
                        amount * MSAT_PER_SAT
                    } else {
                        amount
                    }
                })
                .sum();

            // Check minimum balance threshold for this group
            if group_total_msat < minimum_for_redemption_msat {
                let msg = format!(
                    "⏳ Skipping {} - balance {} msat is below minimum {} msat",
                    client_id, group_total_msat, minimum_for_redemption_msat
                );
                info!("{}", msg);
                cashu_redemption_logger::log_redemption(&msg);
                continue;
            }

            // Select proofs to melt based on configured limit
            let (proofs_to_melt, selected_total_msat) =
                if max_proofs_per_melt > 0 && group_proofs.len() > max_proofs_per_melt {
                    let selected_proofs: Vec<_> =
                        group_proofs.iter().take(max_proofs_per_melt).cloned().collect();
                    let selected_total: u64 = selected_proofs
                        .iter()
                        .map(|p| {
                            let amount: u64 = p.amount.into();
                            if wallet.unit == cdk::nuts::CurrencyUnit::Sat {
                                amount * MSAT_PER_SAT
                            } else {
                                amount
                            }
                        })
                        .sum();

                    let msg = format!(
                        "⚠️ Limiting to {} proofs ({} sats) for {}",
                        selected_proofs.len(),
                        selected_total / MSAT_PER_SAT,
                        client_id
                    );
                    info!("{}", msg);
                    cashu_redemption_logger::log_redemption(&msg);

                    (selected_proofs, selected_total)
                } else {
                    (group_proofs.clone(), group_total_msat)
                };

            // Calculate fee reserve
            let percentage_fee_selected =
                ((selected_total_msat as f64) * (fee_reserve_percent / 100.0)) as u64;
            let fee_reserve_selected_msat = percentage_fee_selected.max(min_fee_reserve_msat);

            if selected_total_msat <= fee_reserve_selected_msat {
                let msg = format!(
                    "⚠️ Insufficient balance after fee reserve for {}: {} msat <= {} msat fees",
                    client_id, selected_total_msat, fee_reserve_selected_msat
                );
                warn!("{}", msg);
                cashu_redemption_logger::log_redemption(&msg);
                continue;
            }

            let redeemable_amount_msat = selected_total_msat - fee_reserve_selected_msat;

            let msg = format!(
                "💡 Redemption plan for {}: {} proofs → {} msat - {} msat fees = {} msat",
                client_id, proofs_to_melt.len(), selected_total_msat,
                fee_reserve_selected_msat, redeemable_amount_msat
            );
            info!("{}", msg);
            cashu_redemption_logger::log_redemption(&msg);

            // Generate Lightning invoice
            let memo = format!(
                "Redeeming {} proofs from {} for {}",
                proofs_to_melt.len(),
                wallet.mint_url,
                client_id
            );

            let (invoice, _payment_hash) = if is_multi_tenant {
                // Multi-tenant LNURL mode: Create LNURL client for each tenant's address
                let ln_client_config = lnclient::LNClientConfig {
                    ln_client_type: "LNURL".to_string(),
                    lnd_config: None,
                    lnurl_config: Some(lnurl::LNURLOptions { address: client_id.clone() }),
                    nwc_config: None,
                    cln_config: None,
                    root_key: std::env::var("ROOT_KEY")
                        .unwrap_or_else(|_| "root_key".to_string())
                        .as_bytes()
                        .to_vec(),
                };

                match lnurl::LnAddressUrlResJson::new_client(&ln_client_config).await {
                    Ok(ln_client) => {
                        let ln_client_conn = lnclient::LNClientConn { ln_client };
                        match ln_client_conn
                            .generate_invoice(lnrpc::Invoice {
                                value_msat: redeemable_amount_msat as i64,
                                memo: memo.clone(),
                                ..Default::default()
                            })
                            .await
                        {
                            Ok((invoice, payment_hash)) => {
                                cashu_redemption_logger::log_redemption(&format!(
                                    "✅ Generated invoice via LNURL {}: payment_hash={}",
                                    client_id, payment_hash
                                ));
                                (invoice, payment_hash)
                            }
                            Err(e) => {
                                let msg = format!(
                                    "❌ Failed to generate invoice via LNURL {}: {}",
                                    client_id, e
                                );
                                error!("{}", msg);
                                cashu_redemption_logger::log_redemption(&msg);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        let msg = format!(
                            "❌ Failed to create LNURL client for {}: {}",
                            client_id, e
                        );
                        error!("{}", msg);
                        cashu_redemption_logger::log_redemption(&msg);
                        continue;
                    }
                }
            } else {
                // Single-tenant mode: Use the configured LN client (LND, CLN, NWC, or default LNURL)
                let ln_client = match LN_CLIENT.get() {
                    Some(client) => client.clone(),
                    None => {
                        let msg = "❌ LN client not initialized for single-tenant redemption";
                        error!("{}", msg);
                        cashu_redemption_logger::log_redemption(msg);
                        continue;
                    }
                };

                let ln_client_conn = lnclient::LNClientConn { ln_client };
                match ln_client_conn
                    .generate_invoice(lnrpc::Invoice {
                        value_msat: redeemable_amount_msat as i64,
                        memo: memo.clone(),
                        ..Default::default()
                    })
                    .await
                {
                    Ok((invoice, payment_hash)) => {
                        let client_type = LN_CLIENT_TYPE.get().map_or("unknown", |s| s.as_str());
                        cashu_redemption_logger::log_redemption(&format!(
                            "✅ Generated invoice via {}: payment_hash={}",
                            client_type, payment_hash
                        ));
                        (invoice, payment_hash)
                    }
                    Err(e) => {
                        let msg = format!("❌ Failed to generate invoice: {}", e);
                        error!("{}", msg);
                        cashu_redemption_logger::log_redemption(&msg);
                        continue;
                    }
                }
            };

            // Get melt quote
            cashu_redemption_logger::log_redemption(&format!(
                "🔥 Getting melt quote for {} proofs...",
                proofs_to_melt.len()
            ));

            let quote = match wallet_clone.melt_quote(invoice.clone(), None).await {
                Ok(q) => {
                    let actual_fee_reserve_sats: u64 = q.fee_reserve.into();
                    let amount_sats: u64 = q.amount.into();
                    let (actual_fee_reserve_msat, amount_msat) =
                        if wallet.unit == cdk::nuts::CurrencyUnit::Sat {
                            (actual_fee_reserve_sats * MSAT_PER_SAT, amount_sats * MSAT_PER_SAT)
                        } else {
                            (actual_fee_reserve_sats, amount_sats)
                        };

                    let msg = format!(
                        "📋 Melt quote for {}: amount={} msat, fee_reserve={} msat",
                        client_id, amount_msat, actual_fee_reserve_msat
                    );
                    info!("{}", msg);
                    cashu_redemption_logger::log_redemption(&msg);

                    let required_total_msat = amount_msat + actual_fee_reserve_msat;
                    if selected_total_msat < required_total_msat {
                        let msg = format!(
                            "⚠️ Fee reserve insufficient for {}: {} msat < {} msat required",
                            client_id, selected_total_msat, required_total_msat
                        );
                        warn!("{}", msg);
                        cashu_redemption_logger::log_redemption(&msg);
                        continue;
                    }

                    q
                }
                Err(e) => {
                    let msg = format!(
                        "❌ Failed to create melt quote for {}: {}",
                        client_id, e
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
                        info!(
                            "🔓 Melting {} P2PK-locked proofs for {}",
                            proofs_to_melt.len(),
                            client_id
                        );

                        let mut signed_proofs = proofs_to_melt.clone();
                        for proof in &mut signed_proofs {
                            if let Err(e) = proof.sign_p2pk(private_key.clone()) {
                                error!("❌ Failed to sign proof: {:?}", e);
                            }
                        }

                        wallet_clone.melt_proofs(&quote.id, signed_proofs).await
                    } else {
                        wallet_clone.melt(&quote.id).await
                    }
                } else {
                    wallet_clone.melt(&quote.id).await
                }
            } else {
                wallet_clone.melt(&quote.id).await
            };

            // Process melt result
            match melt_result {
                Ok(result) => {
                    let result_msg = format!("🔍 Melt result for {}: {:?}", client_id, result);
                    info!("{}", result_msg);
                    cashu_redemption_logger::log_redemption(&result_msg);

                    let actual_fees_sats: u64 = quote.fee_reserve.into();
                    let actual_fees_msat = if wallet.unit == cdk::nuts::CurrencyUnit::Sat {
                        actual_fees_sats * MSAT_PER_SAT
                    } else {
                        actual_fees_sats
                    };
                    total_fees_paid_msat += actual_fees_msat;

                    let msg = format!(
                        "✅ Redeemed {} proofs for {}: {} msat to Lightning",
                        proofs_to_melt.len(), client_id, redeemable_amount_msat
                    );
                    info!("{}", msg);
                    cashu_redemption_logger::log_redemption(&msg);
                    total_redeemed += proofs_to_melt.len();
                    total_amount_redeemed_msat += redeemable_amount_msat;

                    // Clean up Redis proof-to-lnurl mappings for melted proofs
                    if let Err(e) = remove_proof_lnurl_mappings(&proofs_to_melt) {
                        warn!("⚠️ Failed to clean up proof mappings for {}: {}", client_id, e);
                    }
                }
                Err(e) => {
                    let msg = format!(
                        "❌ Failed to melt proofs for {}: {}",
                        client_id, e
                    );
                    error!("{}", msg);
                    cashu_redemption_logger::log_redemption(&msg);
                }
            }
        } // end of lnurl group loop
    } // end of mint loop

    let msg = format!(
        "✅ Smart Cashu redemption completed: {} proofs → {} msat to Lightning + {} msat fees",
        total_redeemed, total_amount_redeemed_msat, total_fees_paid_msat
    );
    info!("{}", msg);
    cashu_redemption_logger::log_redemption(&msg);
    Ok(total_redeemed > 0)
}
