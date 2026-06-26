//! `ngx_l402_core` — pure, dependency-light logic extracted from the main
//! `ngx_l402` nginx module so it can be unit-tested with plain `cargo test`.
//!
//! The main crate is a `cdylib` that links nginx via `nginx-sys`; a test binary
//! built from it can't resolve nginx's runtime-provided symbols, so it can't
//! host runnable unit tests. The custody-critical pure pieces — wallet-seed
//! derivation today — live here instead, where `cargo test -p ngx_l402_core`
//! runs in seconds with no nginx and no Docker. A silent change to any of these
//! can strand user funds, so each is pinned by tests in its own module.

mod fee;
mod l402_header;
mod p2pk;
mod wallet_seed;

pub use fee::fee_reserve_msat;
pub use l402_header::parse_l402_header_value;
pub use p2pk::{parse_p2pk_secret_key, InvalidP2pkKey};
pub use wallet_seed::{
    derive_wallet_seed, generate_mnemonic, is_valid_mnemonic, InvalidMnemonic, WALLET_SEED_LEN,
};
