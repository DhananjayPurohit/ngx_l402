# Multi-Tenant Configuration

The module supports **multi-tenant mode**, allowing different API routes to use different Lightning/LNURL backends. This is useful for platforms hosting multiple merchants or services, where each tenant receives payments to their own wallet.

> **Current Support**: Multi-tenant is currently supported for **Cashu eCash payments only** when using `LN_CLIENT_TYPE=LNURL`.

---

## How It Works

1. **Per-location LNURL addresses**: Use the `l402_lnurl_addr` directive to specify a different LNURL address per Nginx location block.
2. **Proof tracking**: When a Cashu token is received, the proofs are mapped to the tenant's LNURL address in Redis.
3. **Grouped redemption**: The automatic redemption task groups proofs by tenant and redeems each group to the correct LNURL address.

---

## Nginx Configuration

```nginx
# Tenant 1 — payments go to alice@getalby.com
location /api/tenant1 {
    l402 on;
    l402_amount_msat_default 10000;
    l402_macaroon_timeout 0;
    l402_lnurl_addr "alice@getalby.com";
}

# Tenant 2 — payments go to bob@getalby.com
location /api/tenant2 {
    l402 on;
    l402_amount_msat_default 15000;
    l402_macaroon_timeout 0;
    l402_lnurl_addr "bob@getalby.com";
}

# Tenant 3 — self-hosted LNURL server
location /api/tenant3 {
    l402 on;
    l402_amount_msat_default 5000;
    l402_macaroon_timeout 0;
    l402_lnurl_addr "user@your-lnurl-server.com";
}
```

---

## Required Environment Variables

```bash
# Use LNURL client type
Environment=LN_CLIENT_TYPE=LNURL

# Default LNURL address (fallback when l402_lnurl_addr is not set)
Environment=LNURL_ADDRESS=default@your-domain.com

# Redis is required for proof-to-tenant mapping
Environment=REDIS_URL=redis://127.0.0.1:6379

# Enable Cashu eCash support
Environment=CASHU_ECASH_SUPPORT=true
Environment=CASHU_WALLET_SECRET=<your-secret>
Environment=CASHU_WHITELISTED_MINTS=https://mint.example.com

# Enable automatic redemption to Lightning
Environment=CASHU_REDEEM_ON_LIGHTNING=true
Environment=CASHU_REDEMPTION_INTERVAL_SECS=60
```

---

## Dynamic LNURL Override via Redis

You can also override the LNURL address per path dynamically without reloading Nginx:

```bash
SET lnurl:/api/tenant1 alice@getalby.com
SET lnurl:/api/tenant2 bob@getalby.com
```

See [Redis & Dynamic Config](./config-redis.md) for more details.
