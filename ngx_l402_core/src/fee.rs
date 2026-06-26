//! Lightning melt fee-reserve calculation.
//!
//! When redeeming Cashu proofs to Lightning, a fee reserve is held back so the
//! melt's actual routing fee is covered. The reserve is a percentage of the
//! amount, floored at a configured minimum. Get this wrong and every redemption
//! over- or under-reserves, so the calculation is a pure function pinned by
//! tests.

/// Compute the Lightning fee reserve, in millisatoshis, to hold back from a
/// redemption of `amount_msat`: `percent`% of the amount, but never less than
/// `min_reserve_msat`. Matches the truncating `as u64` behaviour of the
/// production melt loop exactly.
pub fn fee_reserve_msat(amount_msat: u64, percent: f64, min_reserve_msat: u64) -> u64 {
    let percentage_fee = ((amount_msat as f64) * (percent / 100.0)) as u64;
    percentage_fee.max(min_reserve_msat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentage_applies_above_floor() {
        // 1% of 1_000_000 msat = 10_000, well above the 1_000 floor.
        assert_eq!(fee_reserve_msat(1_000_000, 1.0, 1_000), 10_000);
    }

    #[test]
    fn floor_applies_when_percentage_is_smaller() {
        // 1% of 10_000 = 100, below the 5_000 floor -> floor wins.
        assert_eq!(fee_reserve_msat(10_000, 1.0, 5_000), 5_000);
    }

    #[test]
    fn zero_percent_yields_the_floor() {
        assert_eq!(fee_reserve_msat(1_000_000, 0.0, 2_000), 2_000);
    }

    #[test]
    fn zero_amount_yields_the_floor() {
        assert_eq!(fee_reserve_msat(0, 1.0, 1_500), 1_500);
    }

    /// Fractional percentages truncate (not round) to match `as u64`.
    #[test]
    fn fractional_percent_truncates() {
        // 0.1% of 12_345 = 12.345 -> truncated to 12.
        assert_eq!(fee_reserve_msat(12_345, 0.1, 0), 12);
    }

    #[test]
    fn handles_large_amounts() {
        // 1% of 1 BTC (in msat) = 1_000_000_000 msat; no overflow, exact.
        assert_eq!(fee_reserve_msat(100_000_000_000, 1.0, 0), 1_000_000_000);
    }
}
