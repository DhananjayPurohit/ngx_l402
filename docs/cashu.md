# Cashu eCash

The module supports [Cashu](https://cashu.space) eCash tokens as an alternative payment method to Lightning invoices.

---

## Standard Mode vs P2PK Mode

| | Standard Mode | P2PK Mode |
|---|---|---|
| **How it works** | Calls `wallet.receive()` → contacts mint to swap tokens | Verifies token locked to proxy's public key locally |
| **Speed** | Slower (blocks on mint API call per request) | Fast (milliseconds — no mint call!) |
| **Best for** | Low-traffic or simple setups | High-traffic production deployments |
| **Extra requirement** | None | `CASHU_WHITELISTED_MINTS` is required |

---

## Standard Mode Setup

```bash
Environment=CASHU_ECASH_SUPPORT=true
Environment=CASHU_DB_PATH=/var/lib/nginx/cashu_tokens.db
Environment=CASHU_WALLET_SECRET=<your-secret-random-string>

# Optional: Whitelist specific mints (comma-separated)
Environment=CASHU_WHITELISTED_MINTS=https://mint1.example.com,https://mint2.example.com

# Optional: Auto-redeem to Lightning
Environment=CASHU_REDEEM_ON_LIGHTNING=true
Environment=CASHU_REDEMPTION_INTERVAL_SECS=3600
```

> **⚠️ Security**: `CASHU_WALLET_SECRET` is used to generate the wallet seed. Anyone with this secret can steal your tokens! Generate with `openssl rand -hex 32` and never commit it to Git.

---

## P2PK Mode Setup (High Performance)

```bash
Environment=CASHU_P2PK_MODE=true
Environment=CASHU_P2PK_PRIVATE_KEY=<your-private-key-hex>
# CASHU_WHITELISTED_MINTS is REQUIRED in P2PK mode
Environment=CASHU_WHITELISTED_MINTS=https://mint1.example.com
```

> **⚠️ Security**: `CASHU_P2PK_PRIVATE_KEY` is equally critical. Anyone with this key can spend tokens locked to your public key. Generate with `openssl rand -hex 32`.

**How P2PK mode works per request:**

1. Proxy derives a public key from `CASHU_P2PK_PRIVATE_KEY` and sends it to clients via the `X-Cashu` header (NUT-24)
2. Client creates P2PK-locked tokens to that public key
3. Proxy verifies tokens are locked to its public key (NUT-11) — local check, no network call
4. Proxy unlocks proofs with private key (local cryptographic operation)
5. Unlocked proofs are stored directly in CDK database via `wallet.receive_proofs()`
6. Background redemption task finds proofs via `wallet.get_unspent_proofs()` and redeems to Lightning via `wallet.melt()`

---

## Redemption Fee Configuration

```bash
# Minimum balance to attempt melting (default: 10 sats)
Environment=CASHU_MELT_MIN_BALANCE_SATS=10

# Percentage to reserve for fees (default: 1%)
Environment=CASHU_MELT_FEE_RESERVE_PERCENT=1

# Minimum fee reserve when percentage is small (default: 4 sats)
Environment=CASHU_MELT_MIN_FEE_RESERVE_SATS=4

# Maximum proofs per melt operation (default: 0 = unlimited)
# Use this if your mint has a per-melt proof limit (e.g. mint.coinos.io = 1000)
Environment=CASHU_MAX_PROOFS_PER_MELT=1000
```

**Fee calculation**: `fee_reserve = max(total_amount × percent/100, min_fee_sats)`

**Example 1** — Large balance (500 sats) with 1% fee reserve:
- Percentage fee: `500 × 1% = 5 sats`
- Minimum fee: `4 sats`
- Used reserve: `max(5, 4) = 5 sats`
- Redeemable: `500 - 5 = 495 sats`

**Example 2** — Small balance (50 sats) with 1% fee reserve:
- Percentage fee: `50 × 1% = 0.5 sats`
- Minimum fee: `4 sats`
- Used reserve: `max(0.5, 4) = 4 sats` ← Minimum kicks in!
- Redeemable: `50 - 4 = 46 sats`

**Example 3** — Proof count limiting when exceeding mint limit (`CASHU_MAX_PROOFS_PER_MELT=1000`):
- **Scenario**: 1282 proofs worth 13,588 sats total
- **Check**: `1282 proofs > 1000 limit` → Limiting triggered
- **Action**: Select first 1000 proofs worth ~10,600 sats
- **Invoice**: Generate invoice for 10,600 sats
- **Remaining**: 282 proofs (~2,988 sats) stay for next cycle
- **Next cycle**: `282 proofs < 1000 limit` → all remaining proofs melted

> Actual melt quote fees are verified against the reserve; warnings appear if the reserve was insufficient.

> **Note on `CASHU_WHITELISTED_MINTS`**: If not configured, all mints are accepted in standard mode. **In P2PK mode, whitelisted mints are REQUIRED** for security and the payment request (NUT-24).

---

## SQLite Database Setup

```bash
# One-time setup — persists across restarts
sudo mkdir -p /var/lib/nginx
sudo chown nginx:nginx /var/lib/nginx
sudo chmod 755 /var/lib/nginx
```

The `cdk-sqlite` crate automatically creates the database file and tables. Database location: `/var/lib/nginx/cashu_tokens.db`
