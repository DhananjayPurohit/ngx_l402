//! Prometheus-format counters for ngx_l402.
//!
//! Counters are global [`AtomicU64`]s updated from the access handler on the
//! hot path; exposition format is rendered lazily via [`render`] when an
//! operator scrapes the `l402_metrics` endpoint.
//!
//! No label dimensions are used — per-route or per-backend granularity is
//! intentionally left to the structured JSON log line emitted for each
//! dry-run request (see `handle_dry_run_passthrough` in `lib.rs`).

use core::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($($(#[$attr:meta])* $name:ident),* $(,)?) => {
        $(
            $(#[$attr])*
            pub static $name: AtomicU64 = AtomicU64::new(0);
        )*
    };
}

counters! {
    /// Every request that entered the L402 access handler with `l402 on;`,
    /// regardless of whether enforcement was active.
    L402_REQUESTS_TOTAL,

    /// Requests that resulted in a 402 Payment Required response (enforced mode).
    L402_CHALLENGES_ISSUED_TOTAL,

    /// Requests whose Authorization header verified successfully.
    L402_PAYMENTS_VALID_TOTAL,

    /// Requests whose Authorization header failed verification (401).
    L402_PAYMENTS_INVALID_TOTAL,

    /// Requests that arrived without an Authorization header.
    L402_PAYMENTS_MISSING_TOTAL,

    /// Requests rejected with 429 by `l402_invoice_rate_limit` (enforce mode).
    L402_RATE_LIMITED_TOTAL,

    /// Total requests handled in dry-run (shadow) mode.
    L402_DRY_RUN_REQUESTS_TOTAL,

    /// Dry-run requests that *would* have been blocked (401 or 402) in
    /// enforce mode.
    L402_DRY_RUN_WOULD_BLOCK_TOTAL,

    /// Dry-run requests that *would* have been allowed through (valid token).
    L402_DRY_RUN_WOULD_ALLOW_TOTAL,

    /// Dry-run requests where challenge synthesis (invoice generation) failed.
    L402_DRY_RUN_CHALLENGE_ERRORS_TOTAL,

    /// Dry-run requests that would have been rejected with 429 by the
    /// invoice rate limiter had enforcement been on.
    L402_DRY_RUN_RATE_LIMITED_TOTAL,

    /// Sum of msat prices evaluated for dry-run requests. Divide by
    /// `l402_dry_run_requests_total` for an average-price gauge.
    L402_DRY_RUN_PRICE_MSAT_SUM,
}

#[inline]
pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

/// Render all counters in Prometheus text exposition format (version 0.0.4).
pub fn render() -> String {
    const ENTRIES: &[(&str, &str, &AtomicU64)] = &[
        (
            "l402_requests_total",
            "Total L402-protected requests seen by the access handler.",
            &L402_REQUESTS_TOTAL,
        ),
        (
            "l402_challenges_issued_total",
            "L402 challenges returned to clients (HTTP 402 in enforce mode).",
            &L402_CHALLENGES_ISSUED_TOTAL,
        ),
        (
            "l402_payments_valid_total",
            "Authorization headers that verified successfully.",
            &L402_PAYMENTS_VALID_TOTAL,
        ),
        (
            "l402_payments_invalid_total",
            "Authorization headers that failed verification.",
            &L402_PAYMENTS_INVALID_TOTAL,
        ),
        (
            "l402_payments_missing_total",
            "Requests without an Authorization header.",
            &L402_PAYMENTS_MISSING_TOTAL,
        ),
        (
            "l402_rate_limited_total",
            "Requests rejected with 429 by l402_invoice_rate_limit.",
            &L402_RATE_LIMITED_TOTAL,
        ),
        (
            "l402_dry_run_requests_total",
            "Requests handled in dry-run (shadow) mode.",
            &L402_DRY_RUN_REQUESTS_TOTAL,
        ),
        (
            "l402_dry_run_would_block_total",
            "Dry-run requests that would have been blocked in enforce mode.",
            &L402_DRY_RUN_WOULD_BLOCK_TOTAL,
        ),
        (
            "l402_dry_run_would_allow_total",
            "Dry-run requests that would have been allowed through in enforce mode.",
            &L402_DRY_RUN_WOULD_ALLOW_TOTAL,
        ),
        (
            "l402_dry_run_challenge_errors_total",
            "Dry-run requests where L402 challenge synthesis failed.",
            &L402_DRY_RUN_CHALLENGE_ERRORS_TOTAL,
        ),
        (
            "l402_dry_run_rate_limited_total",
            "Dry-run requests that would have been rate-limited in enforce mode.",
            &L402_DRY_RUN_RATE_LIMITED_TOTAL,
        ),
        (
            "l402_dry_run_price_msat_sum",
            "Cumulative msat price evaluated across dry-run requests.",
            &L402_DRY_RUN_PRICE_MSAT_SUM,
        ),
    ];

    let mut out = String::with_capacity(ENTRIES.len() * 128);
    for (name, help, counter) in ENTRIES {
        // writeln! into String is infallible; ignore Result without unwrap.
        let _ = writeln!(out, "# HELP {} {}", name, help);
        let _ = writeln!(out, "# TYPE {} counter", name);
        let _ = writeln!(out, "{} {}", name, counter.load(Ordering::Relaxed));
    }
    out
}
