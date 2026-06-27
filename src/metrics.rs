//! Prometheus-format counters for ngx_l402.
//!
//! Counters live in a single fixed-layout [`MetricsBlock`] of [`AtomicU64`]s.
//! The active block is normally an nginx **shared-memory** allocation installed
//! by the master process before it forks workers (see `register_metrics_shm` in
//! `lib.rs`), so every worker increments the *same* physical atomics and a
//! `/metrics` scrape served by any worker returns the true cross-worker total
//! (issue #105).
//!
//! If the shared zone is unavailable — registration or slab allocation failed —
//! the active block falls back to a process-local [`static`], degrading to the
//! old per-worker counts rather than crashing. The hot-path cost is identical
//! either way: a single relaxed `fetch_add` on a memory address.
//!
//! No label dimensions are used — per-route or per-backend granularity is
//! intentionally left to the structured JSON log line emitted for each
//! dry-run request (see `handle_dry_run_passthrough` in `lib.rs`).

use core::fmt::Write;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

/// Stable index for each counter.
///
/// The numeric discriminants are part of the shared-memory layout: counters
/// can be carried over across an `nginx -s reload` that reuses the segment, so
/// **only append** new variants at the end. Reordering or removing a variant
/// changes the meaning of already-stored slots. Any layout change must bump
/// [`MAGIC`] so a reused segment from an incompatible build is re-initialised.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Metric {
    /// Every request that entered the L402 access handler with `l402 on;`,
    /// regardless of whether enforcement was active.
    RequestsTotal = 0,
    /// Requests that resulted in a 402 Payment Required response (enforced mode).
    ChallengesIssuedTotal,
    /// Requests whose Authorization header verified successfully. Aggregate of
    /// [`Metric::PaymentsLightningTotal`] and [`Metric::PaymentsCashuTotal`].
    PaymentsValidTotal,
    /// Successful payments settled via a Lightning macaroon (classic preimage
    /// path *or* auto-detect path).
    PaymentsLightningTotal,
    /// Successful payments settled via a Cashu token redemption.
    PaymentsCashuTotal,
    /// Requests whose Authorization header failed verification (401).
    PaymentsInvalidTotal,
    /// Requests that arrived without an Authorization header.
    PaymentsMissingTotal,
    /// Lightning invoices successfully generated as part of a 402 challenge.
    InvoicesGeneratedTotal,
    /// Lightning invoice generation failures that resulted in a 500 response.
    InvoicesGenerationErrorsTotal,
    /// Requests rejected with 429 by `l402_invoice_rate_limit` (enforce mode).
    RateLimitedTotal,
    /// Total requests handled in dry-run (shadow) mode.
    DryRunRequestsTotal,
    /// Dry-run requests that *would* have been blocked (401 or 402) in enforce mode.
    DryRunWouldBlockTotal,
    /// Dry-run requests that *would* have been allowed through (valid token).
    DryRunWouldAllowTotal,
    /// Dry-run requests where challenge synthesis (invoice generation) failed.
    DryRunChallengeErrorsTotal,
    /// Dry-run requests that would have been rejected with 429 by the invoice
    /// rate limiter had enforcement been on.
    DryRunRateLimitedTotal,
    /// Sum of msat prices evaluated for dry-run requests. Divide by
    /// `l402_dry_run_requests_total` for an average-price gauge.
    DryRunPriceMsatSum,
}

impl Metric {
    /// Number of counters in [`MetricsBlock`]. Must equal the count of [`Metric`]
    /// variants and the length of [`ENTRIES`].
    pub const COUNT: usize = 16;
}

// Compile-time guards keeping the enum, `COUNT`, and `ENTRIES` in lockstep:
//   * the last variant's discriminant must be `COUNT - 1`, so appending a
//     variant without bumping `COUNT` (or vice versa) fails to compile;
//   * `ENTRIES` is typed `[_; Metric::COUNT]`, so its length is pinned to
//     `COUNT` by the array type itself.
// Together these make a misindexed Prometheus label impossible to introduce
// silently.
const _: () = assert!(Metric::DryRunPriceMsatSum as usize + 1 == Metric::COUNT);

/// Prometheus metric name + HELP text for each counter, in [`Metric`] order.
/// The index of each row must match the corresponding [`Metric`] discriminant.
static ENTRIES: [(&str, &str); Metric::COUNT] = [
    (
        "l402_requests_total",
        "Total L402-protected requests seen by the access handler.",
    ),
    (
        "l402_challenges_issued_total",
        "L402 challenges returned to clients (HTTP 402 in enforce mode).",
    ),
    (
        "l402_payments_valid_total",
        "Authorization headers that verified successfully (Lightning + Cashu).",
    ),
    (
        "l402_payments_lightning_total",
        "Successful payments settled via a Lightning macaroon.",
    ),
    (
        "l402_payments_cashu_total",
        "Successful payments settled via a Cashu token redemption.",
    ),
    (
        "l402_payments_invalid_total",
        "Authorization headers that failed verification.",
    ),
    (
        "l402_payments_missing_total",
        "Requests without an Authorization header.",
    ),
    (
        "l402_invoices_generated_total",
        "Lightning invoices successfully generated for L402 challenges.",
    ),
    (
        "l402_invoices_generation_errors_total",
        "Failures generating a Lightning invoice during L402 challenge synthesis.",
    ),
    (
        "l402_rate_limited_total",
        "Requests rejected with 429 by l402_invoice_rate_limit.",
    ),
    (
        "l402_dry_run_requests_total",
        "Requests handled in dry-run (shadow) mode.",
    ),
    (
        "l402_dry_run_would_block_total",
        "Dry-run requests that would have been blocked in enforce mode.",
    ),
    (
        "l402_dry_run_would_allow_total",
        "Dry-run requests that would have been allowed through in enforce mode.",
    ),
    (
        "l402_dry_run_challenge_errors_total",
        "Dry-run requests where L402 challenge synthesis failed.",
    ),
    (
        "l402_dry_run_rate_limited_total",
        "Dry-run requests that would have been rate-limited in enforce mode.",
    ),
    (
        "l402_dry_run_price_msat_sum",
        "Cumulative msat price evaluated across dry-run requests.",
    ),
];

/// Sentinel written into a freshly-initialised [`MetricsBlock`]. Lets the shm
/// zone init callback detect a reused segment that was populated by a
/// *compatible* build and reuse its counters; a mismatch (e.g. after a binary
/// upgrade that changed the layout) triggers re-initialisation. Bump the low
/// bytes whenever [`Metric`]/[`MetricsBlock`] layout changes.
const MAGIC: u64 = 0x4c34_3032_4d54_0001; // 'L402MT' + layout version 0001

/// Fixed-layout block of counters placed either in process-local memory or in
/// an nginx shared-memory zone. `#[repr(C)]` keeps the field order stable so a
/// pointer into shared memory is interpreted identically by every worker.
#[repr(C)]
pub struct MetricsBlock {
    magic: AtomicU64,
    counters: [AtomicU64; Metric::COUNT],
}

impl MetricsBlock {
    const fn new() -> Self {
        MetricsBlock {
            magic: AtomicU64::new(MAGIC),
            counters: [const { AtomicU64::new(0) }; Metric::COUNT],
        }
    }
}

/// Size and alignment of [`MetricsBlock`], for the slab allocation in the shm
/// zone init callback.
pub const BLOCK_SIZE: usize = core::mem::size_of::<MetricsBlock>();
pub const BLOCK_ALIGN: usize = core::mem::align_of::<MetricsBlock>();

/// Process-local fallback used until (or unless) a shared block is installed.
static LOCAL_BLOCK: MetricsBlock = MetricsBlock::new();

/// Active counter store. Null until [`install_shared`] points it at a
/// shared-memory block; reads fall back to [`LOCAL_BLOCK`] while null.
static ACTIVE: AtomicPtr<MetricsBlock> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn block() -> &'static MetricsBlock {
    // Acquire pairs with the Release store in `install_shared`, so a worker that
    // sees a non-null pointer also sees the block's initialised contents.
    let p = ACTIVE.load(Ordering::Acquire);
    if p.is_null() {
        // No shared block installed (registration/alloc failed): use the
        // process-local fallback, i.e. the pre-#105 per-worker behaviour.
        &LOCAL_BLOCK
    } else {
        // SAFETY: a non-null ACTIVE was installed by `install_shared` with a
        // pointer to a valid MetricsBlock in the shared zone, which lives for
        // the lifetime of the process (and is mapped at the same address in
        // every worker via the inherited shared mapping).
        unsafe { &*p }
    }
}

/// Install `ptr` as the active counter store.
///
/// Called from the shm zone init callback in the **master** process before
/// workers fork, so the pointer is inherited by every worker. `ptr` must point
/// at an initialised [`MetricsBlock`] (see [`init_in_place`]) that outlives the
/// process. Passing null reverts to the process-local fallback.
pub fn install_shared(ptr: *mut MetricsBlock) {
    ACTIVE.store(ptr, Ordering::Release);
}

/// Initialise a [`MetricsBlock`] in place at `ptr` (writes the magic header and
/// zeroes all counters).
///
/// # Safety
/// `ptr` must be non-null, [`BLOCK_ALIGN`]-aligned, and valid for writes of
/// [`BLOCK_SIZE`] bytes. The memory must not be concurrently accessed (the shm
/// zone init callback runs single-threaded in the master before fork).
pub unsafe fn init_in_place(ptr: *mut MetricsBlock) {
    core::ptr::write(ptr, MetricsBlock::new());
}

/// Whether the block at `ptr` carries the current [`MAGIC`] (i.e. was
/// initialised by a layout-compatible build).
///
/// # Safety
/// `ptr` must be non-null, aligned, and valid for reads of [`BLOCK_SIZE`] bytes.
pub unsafe fn magic_matches(ptr: *const MetricsBlock) -> bool {
    (*ptr).magic.load(Ordering::Relaxed) == MAGIC
}

#[inline]
pub fn inc(m: Metric) {
    block().counters[m as usize].fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn add(m: Metric, n: u64) {
    block().counters[m as usize].fetch_add(n, Ordering::Relaxed);
}

/// Render all counters in Prometheus text exposition format (version 0.0.4).
pub fn render() -> String {
    let b = block();
    let mut out = String::with_capacity(ENTRIES.len() * 128);
    for (i, (name, help)) in ENTRIES.iter().enumerate() {
        // writeln! into String is infallible; ignore Result without unwrap.
        let _ = writeln!(out, "# HELP {} {}", name, help);
        let _ = writeln!(out, "# TYPE {} counter", name);
        let _ = writeln!(out, "{} {}", name, b.counters[i].load(Ordering::Relaxed));
    }
    out
}
