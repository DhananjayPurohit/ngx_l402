use cdk;
use rand::Rng;
use std::cell::RefCell;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;
use l402_middleware::lnclient;
use tonic_openssl_lnd::lnrpc;
use cdk::cdk_database::WalletDatabase;

// Thread-local storage to track processed tokens
thread_local! {
    static PROCESSED_TOKENS: RefCell<Option<HashSet<String>>> = RefCell::new(None);
}

const MSAT_PER_SAT: u64 = 1000;

// Database singleton
static CASHU_DB: OnceLock<Arc<cdk_sqlite::WalletSqliteDatabase>> = OnceLock::new();

pub fn initialize_cashu(db_path: &str) -> Result<(), String> {
    // Initialize PROCESSED_TOKENS with empty HashSet
    PROCESSED_TOKENS.with(|tokens| {
        *tokens.borrow_mut() = Some(HashSet::new());
    });
    
    // Create runtime for async initialization
    let rt = Runtime::new().expect("Failed to create runtime");
    
    // Initialize database
    rt.block_on(async {
        match cdk_sqlite::WalletSqliteDatabase::new(db_path).await {
            Ok(db) => {
                println!("Cashu database initialized successfully");
                let _ = CASHU_DB.set(Arc::new(db));
                Ok(())
            },
            Err(e) => {
                let error = format!("Failed to create Cashu database: {:?}", e);
                println!("{}", error);
                Err(error)
            }
        }
    })
}

pub async fn verify_cashu_token(token: &str, amount_msat: i64) -> Result<bool, String> {
    // Check if token was already processed
    let token_already_processed = PROCESSED_TOKENS.with(|tokens| {
        if let Some(set) = tokens.borrow().as_ref() {
            set.contains(token)
        } else {
            false
        }
    });

    if token_already_processed {
        println!("Token already processed");
        return Ok(true);
    }

    // Decode the token from string
    let token_decoded = match cdk::nuts::Token::from_str(token) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Failed to decode Cashu token: {}", e);
            return Err(format!("Failed to decode Cashu token: {}", e));
        }
    };
    
    // Check if the token is valid
    if token_decoded.proofs().is_empty() {
        return Ok(false);
    }
    
    // Calculate total token amount in millisatoshis
    let total_amount = token_decoded.value()
        .map_err(|e| format!("Failed to get token value: {}", e))?;

    // Check if the token unit is in millisatoshis or satoshis
    let total_amount_msat: u64 = if token_decoded.unit().unwrap() == cdk::nuts::CurrencyUnit::Sat {
        u64::from(total_amount) * MSAT_PER_SAT
    } else if token_decoded.unit().unwrap() == cdk::nuts::CurrencyUnit::Msat {
        u64::from(total_amount)
    } else {
        // Other units not supported
        return Err(format!("Unsupported token unit: {:?}", token_decoded.unit().unwrap()));
    };
    
    // Check if the token amount is sufficient
    if total_amount_msat < amount_msat as u64 {
        eprintln!("Cashu token amount insufficient: {} msat (required: {} msat)", 
            total_amount_msat, amount_msat);
        return Ok(false);
    }
    
    println!("Successfully decoded Cashu token with {} proofs and {} msat (required: {} msat)", 
        token_decoded.proofs().len(),
        total_amount_msat,
        amount_msat);
    
    // Extract mint URL from the token
    let mint_url = token_decoded.mint_url()
        .map_err(|e| format!("Failed to get mint URL: {}", e))?;

    let unit = token_decoded.unit().unwrap();
    
    // Use the shared database instance
    let db = CASHU_DB.get()
        .ok_or_else(|| "Cashu database not initialized".to_string())?
        .clone();
        
    let seed = rand::rng().random::<[u8; 32]>();
    let wallet = cdk::wallet::Wallet::new(&mint_url.to_string(), unit, db, &seed, None)
        .map_err(|e| format!("Failed to create wallet: {}", e))?;

    match wallet.receive(token, cdk::wallet::ReceiveOptions::default()).await {
        Ok(_) => {
            println!("Cashu token received successful");
            // Add token to processed set after successful receive
            PROCESSED_TOKENS.with(|tokens| {
                if let Some(set) = tokens.borrow_mut().as_mut() {
                    set.insert(token.to_string());
                }
            });
            Ok(true)
        },
        Err(e) => {
            eprintln!("Cashu token receive failed: {}", e);
            Ok(false)
        }
    }
}

pub async fn redeem_to_lightning(ln_client_conn: &lnclient::LNClientConn) -> Result<bool, String> {
    println!("Starting token redemption process...");
    
    // Get database
    let db = CASHU_DB.get()
        .ok_or_else(|| "Cashu database not initialized".to_string())?
        .clone();
    
    // Get mint URLs from database
    let mint_urls_map = db.get_mints().await
        .map_err(|e| format!("Failed to get mint URLs: {}", e))?;
    
    // Create wallets for each mint URL
    let mut wallets = Vec::new();
    for (mint_url, _mint_info) in mint_urls_map {
        let seed = rand::rng().random::<[u8; 32]>();

        // Keeping this as Sat for now but a wallet can hold any unit
        let unit = cdk::nuts::CurrencyUnit::Sat;
        
        match cdk::wallet::Wallet::new(&mint_url.to_string(), unit, db.clone(), &seed, None) {
            Ok(wallet) => wallets.push(wallet),
            Err(e) => eprintln!("Failed to create wallet for {}: {}", mint_url, e),
        }
    }
    
    let multi_mint_wallet = cdk::wallet::MultiMintWallet::new(
        db,
        Arc::new(rand::rng().random::<[u8; 32]>()),
        wallets,
    );

    let mut total_redeemed = 0;
    let mut total_amount_redeemed_msat = 0;

    println!("Mint URLs: {:?}", multi_mint_wallet.get_wallets().await);

    for wallet in multi_mint_wallet.get_wallets().await {
        let wallet_clone = wallet.clone();

        // Calculate total amount
        let total_amount: u64 = wallet_clone.total_balance().await.unwrap().into();

        if total_amount == 0 {
            println!("Total amount is 0 for mint {}", wallet.mint_url);
            continue;
        }

        // Get all spendable proofs
        let proofs = match wallet_clone.get_unspent_proofs().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Failed to get spendable proofs for {}: {}", wallet.mint_url, e);
                continue;
            }
        };

        if proofs.is_empty() {
            println!("No spendable proofs found for mint {}", wallet.mint_url);
            continue;
        }

        // Convert to msats if needed
        let total_amount_msat = if wallet.unit == cdk::nuts::CurrencyUnit::Sat {
            total_amount * MSAT_PER_SAT
        } else {
            total_amount
        };

        println!("Found {} proofs with total value {} msat for mint {}", 
            proofs.len(), total_amount_msat, wallet.mint_url);

        // Generate a Lightning invoice
        let memo = format!("Redeeming {} tokens from {}", proofs.len(), wallet.mint_url);
        let (invoice, payment_hash) = match ln_client_conn.generate_invoice(lnrpc::Invoice {
            value_msat: total_amount_msat as i64,
            memo: memo.clone(),
            ..Default::default()
        }).await {
            Ok((invoice, payment_hash)) => (invoice, payment_hash),
            Err(e) => {
                eprintln!("Failed to generate invoice for {}: {}", wallet.mint_url, e);
                continue;
            }
        };

        println!("Generated invoice for {} msat: {}", total_amount_msat, invoice);

        // Melt the proofs to redeem on Lightning
        match wallet_clone.melt_quote(invoice, None).await {
            Ok(_result) => {
                println!("Successfully redeemed {} proofs ({} msat) for payment hash {}", 
                    proofs.len(), total_amount_msat, payment_hash);
                total_redeemed += proofs.len();
                total_amount_redeemed_msat += total_amount_msat;
            },
            Err(e) => {
                eprintln!("Failed to melt proofs for {}: {}", wallet.mint_url, e);
            }
        }
    }

    println!("Redemption process completed. Redeemed {} proofs totaling {} msat", 
        total_redeemed, total_amount_redeemed_msat);
    Ok(total_redeemed > 0)
}