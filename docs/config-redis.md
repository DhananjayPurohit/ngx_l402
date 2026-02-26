# Redis & Dynamic Configuration

The module supports real-time configuration updates via Redis **without requiring an Nginx reload**.

## Setup

```bash
Environment=REDIS_URL=redis://127.0.0.1:6379
```

---

## Dynamic Pricing

Set the price for a specific path in Redis. Changes are picked up immediately by the next request.

```bash
# Set price to 1000 msats for /api/resource
SET /api/resource 1000

# Set price to 5000 msats for /api/premium
SET /api/premium 5000
```

> **Note**: If no Redis key exists for a path, the module falls back to `l402_amount_msat_default` in `nginx.conf`.

---

## Dynamic LNURL (Per-Tenant Routing)

Override the LNURL address for a specific request path. This takes precedence over `l402_lnurl_addr` in `nginx.conf`.

**Key format**: `lnurl:<request_path>`

```bash
# Route /api/tenant1 payments to alice
SET lnurl:/api/tenant1 alice@getalby.com

# Route /api/tenant2 payments to bob
SET lnurl:/api/tenant2 bob@getalby.com
```

---

## Replay Attack Prevention

Redis is used to enforce single-use of L402 preimages and Cashu tokens, preventing replay attacks across distributed deployments.

```bash
Environment=REDIS_URL=redis://127.0.0.1:6379
Environment=L402_PREIMAGE_TTL_SECONDS=86400      # Default: 24 hours
Environment=L402_CASHU_TOKEN_TTL_SECONDS=86400   # Default: 24 hours
```

**How it works**: After successful verification, SHA256 hashes of preimages/tokens are stored in Redis with a TTL. Subsequent use of the same credential is rejected with `401`. Protection persists across Nginx restarts and works with multiple Nginx instances.
