//! payment_detector.rs
//!
//! Server-side Lightning invoice settlement detection.
//!
//! Instead of requiring the client to include the payment preimage in the
//! `Authorization` header, the server can look up the invoice directly on
//! the Lightning node and retrieve the preimage from there.
//!
//! Supported backends:
//!   - **LND**    — `LookupInvoice` gRPC call
//!   - **CLN**    — `listinvoices` JSON-RPC over unix socket
//!   - **Eclair** — `POST /receivedinfo` REST call
//!   - **NWC**    — not supported (lookup_invoice is optional in NIP-47)
//!   - **LNURL**  — not supported (remote wallet, no query API)

use log::{debug, error, info, warn};
use reqwest::Client as HttpClient;
use std::sync::OnceLock;
use tonic;
use tonic_openssl_lnd::lnrpc;


/// The configured detector (one instance for the lifetime of the worker).
pub static PAYMENT_DETECTOR: OnceLock<PaymentDetector> = OnceLock::new();

pub enum PaymentDetector {
    Lnd(LndDetector),
    Cln(ClnDetector),
    Eclair(EclairDetector),
    Unsupported { reason: String },
}

impl PaymentDetector {
    /// Look up a settled invoice by its payment hash.
    ///
    /// Returns:
    ///   - `Ok(Some(preimage))` — invoice is settled; preimage is returned
    ///   - `Ok(None)`           — invoice exists but is not yet settled
    ///   - `Err(msg)`           — lookup failed or backend unsupported
    pub async fn lookup_settled_invoice(
        &self,
        payment_hash: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        match self {
            PaymentDetector::Lnd(det) => det.lookup(payment_hash).await,
            PaymentDetector::Cln(det) => det.lookup(payment_hash).await,
            PaymentDetector::Eclair(det) => det.lookup(payment_hash).await,
            PaymentDetector::Unsupported { reason } => {
                Err(format!("Auto-detect not supported: {}", reason))
            }
        }
    }
}

/// Called once from `init_module`.  Reads env vars and builds the detector.
pub fn init_payment_detector() {
    let ln_client_type =
        std::env::var("LN_CLIENT_TYPE").unwrap_or_else(|_| "LNURL".to_string());

    let detector = match ln_client_type.as_str() {
        "LND" => {
            // LNC mode is not yet supported for lookup (no persistent gRPC stream)
            if std::env::var("LNC_PAIRING_PHRASE").is_ok() {
                warn!("⚠️  LNC mode detected — auto-detect is not supported over LNC mailbox; disabling");
                PaymentDetector::Unsupported {
                    reason: "LNC mailbox does not expose LookupInvoice".into(),
                }
            } else {
                let address = std::env::var("LND_ADDRESS")
                    .unwrap_or_else(|_| "localhost:10009".to_string());
                let macaroon_file = std::env::var("MACAROON_FILE_PATH")
                    .unwrap_or_else(|_| "admin.macaroon".to_string());
                let cert_file = std::env::var("CERT_FILE_PATH")
                    .unwrap_or_else(|_| "tls.cert".to_string());
                info!(
                    "✅ LND payment detector initialised ({})",
                    address
                );
                PaymentDetector::Lnd(LndDetector {
                    address,
                    macaroon_file,
                    cert_file,
                })
            }
        }
        "CLN" | "BOLT12" => {
            let rpc_path = std::env::var("CLN_LIGHTNING_RPC_FILE_PATH")
                .unwrap_or_else(|_| "/root/.lightning/bitcoin/lightning-rpc".to_string());
            info!("✅ CLN payment detector initialised ({})", rpc_path);
            PaymentDetector::Cln(ClnDetector { rpc_path })
        }
        "ECLAIR" => {
            let api_url = std::env::var("ECLAIR_ADDRESS")
                .unwrap_or_else(|_| "http://localhost:8080".to_string());
            let password = std::env::var("ECLAIR_PASSWORD")
                .unwrap_or_else(|_| "password".to_string());
            info!("✅ Eclair payment detector initialised ({})", api_url);
            PaymentDetector::Eclair(EclairDetector { api_url, password })
        }
        "NWC" => {
            warn!("⚠️  NWC backend — lookup_invoice is optional in NIP-47 and not universally supported; disabling auto-detect");
            PaymentDetector::Unsupported {
                reason: "NWC lookup_invoice is not universally supported".into(),
            }
        }
        "LNURL" | _ => {
            warn!(
                "⚠️  {} backend does not support server-side invoice lookup; disabling auto-detect",
                ln_client_type
            );
            PaymentDetector::Unsupported {
                reason: format!("{} cannot query remote wallet invoice state", ln_client_type),
            }
        }
    };

    if PAYMENT_DETECTOR.set(detector).is_err() {
        error!("❌ PAYMENT_DETECTOR already initialised");
    }
}


pub struct LndDetector {
    pub address: String,
    pub macaroon_file: String,
    pub cert_file: String,
}

impl LndDetector {
    pub async fn lookup(&self, payment_hash: &[u8]) -> Result<Option<Vec<u8>>, String> {

        let parts: Vec<&str> = self.address.split(':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid LND_ADDRESS: {}", self.address));
        }
        let host = parts[0].to_string();
        let port: u32 = parts[1]
            .parse()
            .map_err(|_| "Invalid LND port".to_string())?;

        let mut client =
            tonic_openssl_lnd::connect(host, port, self.cert_file.clone(), self.macaroon_file.clone())
                .await
                .map_err(|e| format!("LND connection failed: {}", e))?;

        let request = lnrpc::PaymentHash {
            r_hash: payment_hash.to_vec(),
            ..Default::default()
        };

        let response: tonic::Response<lnrpc::Invoice> = client
            .lightning()
            .lookup_invoice(tonic::Request::new(request))
            .await
            .map_err(|e| format!("LookupInvoice gRPC error: {}", e))?;

        let invoice = response.into_inner();

        // InvoiceState: 0=OPEN, 1=SETTLED, 2=CANCELED, 3=ACCEPTED
        if invoice.state == 1 {
            debug!("✅ LND invoice settled, returning preimage");
            Ok(Some(invoice.r_preimage))
        } else {
            debug!("⏳ LND invoice not yet settled (state={})", invoice.state);
            Ok(None)
        }
    }
}


pub struct ClnDetector {
    pub rpc_path: String,
}

impl ClnDetector {
    /// Uses the CLN JSON-RPC over unix socket via `cln_rpc`.
    pub async fn lookup(&self, payment_hash: &[u8]) -> Result<Option<Vec<u8>>, String> {
        use cln_rpc::model::requests::ListinvoicesRequest;
        use cln_rpc::model::responses::ListinvoicesInvoicesStatus;
        use cln_rpc::ClnRpc;

        let payment_hash_hex = hex::encode(payment_hash);

        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| format!("CLN RPC connect failed: {}", e))?;

        let req = ListinvoicesRequest {
            payment_hash: Some(payment_hash_hex.clone()),
            label: None,
            invstring: None,
            offer_id: None,
            index: None,
            start: None,
            limit: None,
        };

        let resp = rpc
            .call_typed(&req)
            .await
            .map_err(|e| format!("CLN listinvoices error: {}", e))?;

        let invoice = match resp.invoices.into_iter().next() {
            Some(inv) => inv,
            None => {
                warn!("⚠️  CLN: no invoice found for payment_hash {}", &payment_hash_hex[..16]);
                return Ok(None);
            }
        };

        if invoice.status == ListinvoicesInvoicesStatus::PAID {
            match invoice.payment_preimage {
                Some(preimage_secret) => {
                    debug!("✅ CLN invoice settled");
                    // Secret has a public to_vec() method
                    Ok(Some(preimage_secret.to_vec()))
                }
                None => Err("CLN invoice settled but preimage missing".into()),
            }
        } else {
            debug!("⏳ CLN invoice not yet settled (status={:?})", invoice.status);
            Ok(None)
        }
    }
}


pub struct EclairDetector {
    pub api_url: String,
    pub password: String,
}

impl EclairDetector {
    pub async fn lookup(&self, payment_hash: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let payment_hash_hex = hex::encode(payment_hash);
        let url = format!("{}/receivedinfo", self.api_url.trim_end_matches('/'));

        let client = HttpClient::new();
        let resp = client
            .post(&url)
            .basic_auth("", Some(&self.password))
            .form(&[("paymentHash", &payment_hash_hex)])
            .send()
            .await
            .map_err(|e| format!("Eclair HTTP error: {}", e))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            warn!("⚠️  Eclair: invoice not found for payment_hash {}", &payment_hash_hex[..16]);
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(format!("Eclair /receivedinfo returned HTTP {}", resp.status()));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Eclair JSON parse error: {}", e))?;

        // Eclair returns {"status": {"type": "received", ...}, "paymentPreimage": "hex"}
        let status_type = body
            .get("status")
            .and_then(|s| s.get("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("");

        if status_type == "received" {
            let preimage_hex = body
                .get("paymentPreimage")
                .and_then(|p| p.as_str())
                .ok_or_else(|| "Eclair: paymentPreimage field missing".to_string())?;

            debug!("✅ Eclair invoice settled");
            hex::decode(preimage_hex)
                .map(Some)
                .map_err(|e| format!("Failed to hex-decode Eclair preimage: {}", e))
        } else {
            debug!("⏳ Eclair invoice status={}", status_type);
            Ok(None)
        }
    }
}
