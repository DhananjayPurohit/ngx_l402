use cdk;
use cdk::localstore::LocalStore;
use cdk::mint::Mint;
use cdk::nuts::{Amount, CurrencyUnit, Invoice, MeltResponse, Proof, Token};
use cdk::wallet::{ReceiveOptions, Wallet};
use log::{debug, error, info, warn};
use l402_middleware::lnclient;
use std::cell::RefCell;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;
use tonic_openssl_lnd::lnrpc;

use crate::cashu_redemption_logger;

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

pub fn is_p2pk_mode_enabled() -> bool {
    P2PK_MODE_ENABLED.get().copied().unwrap_or(false)
}

pub fn is_cashu_ecash_enabled() -> bool {
    CASHU_ECASH_ENABLED.get().copied().unwrap_or(false)
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

pub async fn verify_cashu_token(token: &str, amount_msat: i64) -> Result<bool, String> {
    debug!("🔍 Verifying Cashu token, checking database connection...");

    // Check if token was already processed in this thread's context
    if PROCESSED_TOKENS.with(|tokens| {
        tokens
            .borrow()
            .as_ref()
            .map_or(false, |set| set.contains(token))
    }) {
        debug!("✅ Cashu token already processed in this context");
        return Ok(true);
    }

    // Decode the token from string
    let token_decoded = Token::from_str(token)
        .map_err(|e| format!("Failed to decode Cashu token: {}", e))?;

    let invoice_amount_sat = (amount_msat as u64) / MSAT_PER_SAT;
    info!("🪙 Attempting to redeem Cashu token for {} sats", invoice_amount_sat);

    // Get DB and create a wallet instance
    let db = CASHU_DB.get().ok_or("Cashu DB not initialized")?.clone();
    let client = Arc::new(cdk::client::reqwest::ReqwestClient::new());
    let wallet = Wallet::new(db.clone(), client.clone(), None);

    // Get mint url from token and check whitelist
    let mint_url = token_decoded.mint_url().cloned().ok_or("Token does not contain a mint URL")?;
    if !is_mint_whitelisted(mint_url.as_str()) {
        warn!("⚠️ Mint URL '{}' is not whitelisted. Redemption rejected.", mint_url);
        return Err(format!("Mint URL '{}' is not whitelisted", mint_url));
    }

    // Receive proofs into the wallet's DB
    wallet.receive(&token_decoded, ReceiveOptions::default()).await
        .map_err(|e| format!("Failed to receive token proofs: {}", e))?;

    // Create a lightning invoice for the required amount
    let mut ln_client = lnclient::get_lnd_client().await.map_err(|e| e.to_string())?;
    let invoice_req = lnrpc::Invoice { memo: "Redeem Cashu token".to_string(), value: invoice_amount_sat as i64, ..Default::default() };
    let invoice_res = ln_client.add_invoice(invoice_req).await.map_err(|e| format!("Failed to create lightning invoice: {}", e))?;
    let invoice_str = invoice_res.into_inner().payment_request;
    let invoice = Invoice::from_str(&invoice_str).map_err(|e| format!("Failed to parse invoice: {}", e))?;
    info!("⚡️ Created lightning invoice for redemption: {}...", &invoice_str[..40]);

    // Select proofs to spend from the wallet
    let proofs_to_send = wallet.select_proofs_for_amount(invoice_amount_sat.into()).await
        .map_err(|e| format!("Not enough value in token to pay for the request: {}", e))?;

    // Calculate amounts for the melt operation
    let invoice_amount = Amount::from(invoice_amount_sat);
    let fee_amount = proofs_to_send.total_amount() - invoice_amount;
    info!("💸 Selected {} in proofs to pay {} invoice (fee: {})", proofs_to_send.total_amount(), invoice_amount, fee_amount);

    // Get a mint client instance and wallet keys
    let mint = Mint::new(mint_url, client);
    let wallet_keys = wallet.keys();

    // Call melt_with_proof_recovery for robust redemption
    info!("熔 Meltdown initiated: Calling melt_with_proof_recovery...");
    let melt_response = mint.melt_with_proof_recovery(
        db.as_ref(),
        &wallet_keys,
        proofs_to_send,
        &invoice,
        invoice_amount,
        fee_amount,
    ).await.map_err(|e| format!("Melt operation failed unexpectedly: {}", e))?;

    if melt_response.paid {
        info!("✅ Cashu token successfully redeemed against invoice.");
        cashu_redemption_logger::log_redemption(token, &invoice_str, amount_msat as u64);

        // Mark token as processed to prevent replay
        PROCESSED_TOKENS.with(|tokens| {
            if let Some(set) = tokens.borrow_mut().as_mut() {
                set.insert(token.to_string());
            }
        });

        Ok(true)
    } else {
        error!("❌ Melt failed but proofs were recovered. Change returned: {:?}. Invoice was not paid.", melt_response.change);
        Err("Failed to redeem Cashu token. Please try again.".to_string())
    }
}