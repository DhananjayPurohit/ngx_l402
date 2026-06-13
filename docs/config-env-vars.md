# Environment Variables

All configuration is done via environment variables set in `nginx.service` (typically at `/lib/systemd/system/nginx.service`).

```ini
[Service]
...
Environment=VAR_NAME=value
```

---

## Lightning Client Type

| Variable | Required | Description |
|---|---|---|
| `LN_CLIENT_TYPE` | ✅ | One of: `LND`, `CLN`, `LNURL`, `NWC`, `BOLT12`, `ECLAIR` |

---

## LND (Direct gRPC)

```bash
Environment=LN_CLIENT_TYPE=LND
Environment=LND_ADDRESS=your-lnd-ip.com
Environment=MACAROON_FILE_PATH=/path/to/macaroon
Environment=CERT_FILE_PATH=/path/to/cert
Environment=ROOT_KEY=your-root-key
```

## LND via Lightning Node Connect (LNC)

```bash
Environment=LN_CLIENT_TYPE=LND
Environment=LNC_PAIRING_PHRASE=<10-word-mnemonic-from-litd>
Environment=LNC_MAILBOX_SERVER=mailbox.terminal.lightning.today:443
Environment=ROOT_KEY=your-root-key
```

## CLN (Core Lightning)

```bash
Environment=LN_CLIENT_TYPE=CLN
Environment=CLN_LIGHTNING_RPC_FILE_PATH=/path/to/lightning-rpc
Environment=ROOT_KEY=your-root-key
```

## LNURL

```bash
Environment=LN_CLIENT_TYPE=LNURL
Environment=LNURL_ADDRESS=username@your-lnurl-server.com
Environment=ROOT_KEY=your-root-key
```

## NWC (Nostr Wallet Connect)

```bash
Environment=LN_CLIENT_TYPE=NWC
Environment=NWC_URI=nostr+walletconnect://<pubkey>?relay=<relay_url>&secret=<secret>
Environment=ROOT_KEY=your-root-key
```

## BOLT12 (Reusable Offers)

```bash
Environment=LN_CLIENT_TYPE=BOLT12
Environment=BOLT12_OFFER=lno1...
Environment=CLN_LIGHTNING_RPC_FILE_PATH=/path/to/lightning-rpc
Environment=ROOT_KEY=your-root-key
```

> **How it works**: When a client requests a protected resource, the module
> connects to your **CLN node** via the Unix socket at `CLN_LIGHTNING_RPC_FILE_PATH`
> and calls `fetchinvoice` to derive a fresh single-use **BOLT11 invoice** from
> the reusable BOLT12 offer. The node resolves the offer's embedded node ID and
> negotiates the payment parameters over the Lightning network automatically.
> `CLN_LIGHTNING_RPC_FILE_PATH` is therefore **required** alongside `BOLT12_OFFER`.

## Eclair

```bash
Environment=LN_CLIENT_TYPE=ECLAIR
Environment=ECLAIR_ADDRESS=http://127.0.0.1:8282
Environment=ECLAIR_PASSWORD=eclairpass   # REQUIRED — no default; module disables auto-detect if unset
Environment=ROOT_KEY=your-root-key
```

> **⚠️ Security**: `ECLAIR_PASSWORD` is **required** and has no default value.
> If it is not set the Eclair payment-detector is disabled at startup and an
> error is logged. Never use a well-known or placeholder password in production.

---

## Redis (Dynamic Pricing & Replay Protection)

> **Strongly recommended in production.** Without Redis, replay protection uses
> in-process caching only — it is lost on restart and does not work across
> multiple nginx workers. Multi-worker deployments **require** Redis.

```bash
Environment=REDIS_URL=redis://127.0.0.1:6379

# Connection pool size (default: 4)
Environment=REDIS_POOL_SIZE=4

# TTL for spent Lightning preimages (default: 86400 = 24 hours)
Environment=L402_PREIMAGE_TTL_SECONDS=86400

# TTL for spent Cashu tokens (default: 86400 = 24 hours)
Environment=L402_CASHU_TOKEN_TTL_SECONDS=86400
```

### Setting TTL to "infinite" (permanent replay protection)

The module stores spent preimages and Cashu tokens in Redis using
`SET NX EX <seconds>`. Redis requires a positive integer for `EX` — there is
no built-in "never expire" option via this command.

To achieve **permanent** replay protection (strongly recommended in production),
set the TTL to a very large value:

```bash
# ~68 years — effectively permanent
Environment=L402_PREIMAGE_TTL_SECONDS=2147483647
Environment=L402_CASHU_TOKEN_TTL_SECONDS=2147483647
```

> **Trade-off**: Permanent keys accumulate in Redis indefinitely. For a busy
> API with many unique tokens this will grow Redis memory over time. Size each
> key at ~100 bytes; 1 million spent tokens ≈ 100 MB.
>
> **Do not set `0`** — Redis rejects `EX 0` with an error, which causes the
> module to fail-open and skip the replay check entirely.

---

## Cashu eCash

```bash
Environment=CASHU_ECASH_SUPPORT=true
Environment=CASHU_DB_PATH=/var/lib/nginx/cashu_tokens.db
Environment=CASHU_WALLET_SECRET=<your-secret-random-string>

# Optional: Whitelist specific mints (comma-separated)
# In standard mode: if not set, all mints are accepted
# In P2PK mode: REQUIRED for security and NUT-24 payment request
Environment=CASHU_WHITELISTED_MINTS=https://mint1.example.com,https://mint2.example.com

# Optional: Auto-redeem Cashu tokens to Lightning
Environment=CASHU_REDEEM_ON_LIGHTNING=true
Environment=CASHU_REDEMPTION_INTERVAL_SECS=3600  # default: 1 hour
```

> **⚠️ Security**: `CASHU_WALLET_SECRET` is used to generate the wallet seed. Anyone with this secret can steal your tokens!
> - Generate with: `openssl rand -hex 32`
> - Never commit to Git
> - Use a different value per deployment/environment
> - Keep it in a secure environment variable or secrets manager

### Redemption Fee Handling

```bash
# Minimum balance to attempt melting (default: 10 sats)
Environment=CASHU_MELT_MIN_BALANCE_SATS=10

# Percentage to reserve for fees (default: 1%)
Environment=CASHU_MELT_FEE_RESERVE_PERCENT=1

# Minimum fee reserve when percentage is small (default: 4 sats)
Environment=CASHU_MELT_MIN_FEE_RESERVE_SATS=4

# Maximum proofs per melt operation (default: 0 = unlimited)
# Logic: if proof_count > limit, select first N proofs, rest remain for next cycle
# Use case: prevent hitting mint proof limits (e.g. mint.coinos.io has 1000 proof limit)
Environment=CASHU_MAX_PROOFS_PER_MELT=1000
```

### P2PK Mode (High Performance)

```bash
Environment=CASHU_P2PK_MODE=true
Environment=CASHU_P2PK_PRIVATE_KEY=<your-private-key-hex>
# Public key is derived automatically from the private key
# CASHU_WHITELISTED_MINTS is REQUIRED in P2PK mode
```

> **⚠️ Security**: `CASHU_P2PK_PRIVATE_KEY` is equally critical. Anyone with this key can spend tokens locked to your public key!
> - Generate with: `openssl rand -hex 32`
> - Never commit to Git or share publicly
> - Keep it secure alongside `CASHU_WALLET_SECRET`

See [Cashu eCash](./cashu.md) for a full explanation of Standard vs P2PK mode and redemption fee examples.

---

## LND via SOCKS5 / Tor proxy

```bash
# [Optional] Route LND gRPC through a SOCKS5 proxy
Environment=SOCKS5_PROXY=socks5://127.0.0.1:9050
```

---

## Capability Manifest Metadata

These optional variables populate the `service` block in `/.well-known/l402-services`.
All are omitted from the manifest JSON when unset.

```bash
Environment=L402_SERVICE_NAME=My API
Environment=L402_SERVICE_DESCRIPTION=Premium data, paid per request.
Environment=L402_SERVICE_OPERATOR=npub1...   # Nostr pubkey, DID, or free-form
Environment=L402_SERVICE_CONTACT=ops@example.com
```

See [Capability Manifest](./manifest.md) for the full manifest spec.

---

## Logging

```bash
Environment=RUST_LOG=info
# For module-specific debug logs:
Environment=RUST_LOG=ngx_l402_lib=debug,info

# Log per-request performance timing (set to any non-empty value to enable)
Environment=L402_PERF_LOG=1
```

---

## Nginx Location Directives

These are set inside `location {}` blocks in `nginx.conf` (not environment variables).

| Directive | Type | Default | Description |
|---|---|---|---|
| `l402` | boolean¹ | `off` | Enable L402 protection for this location |
| `l402_amount_msat_default` | integer | — | Price in millisatoshis (overridden by Redis dynamic pricing) |
| `l402_macaroon_timeout` | integer (seconds) | `0` (disabled) | Macaroon validity window; `0` = no expiry |
| `l402_lnurl_addr` | string | — | Per-location LNURL address for multi-tenant setups |
| `l402_invoice_rate_limit` | `<N>r/m` or `<N>r/s` | disabled | Max invoice generation rate per IP per route |
| `l402_auto_detect_payment` | boolean¹ | `off` | Server-side payment detection — queries the Lightning node instead of requiring the client to supply the preimage |
| `l402_indefinite_access` | boolean¹ | `off` | Skip the single-use preimage replay check — a single payment stays valid for the macaroon lifetime |

> ¹ **Boolean directives** accept: `on` / `off` / `true` / `false` / `1` / `0` / `yes` / `no` (case-insensitive).

### Example: auto-detect enabled location

```nginx
location /protected {
    l402                         on;
    l402_amount_msat_default     10000;
    l402_macaroon_timeout        0;
    l402_auto_detect_payment     on;

    try_files /index.html =404;
}
```

### Example: subscription-style (indefinite) access

```nginx
location /subscriber-only {
    l402                         on;
    l402_amount_msat_default     100000;
    l402_macaroon_timeout        2592000;  # 30 days
    l402_indefinite_access       on;       # single payment stays valid until macaroon expires

    try_files /index.html =404;
}
```

> **Warning**: `l402_indefinite_access on` should always be paired with a non-zero
> `l402_macaroon_timeout`. Without an expiry, the macaroon never expires and the
> same preimage grants access forever.

> **Backends that support auto-detect**: `LND`, `CLN`, `BOLT12`, `ECLAIR`.
> `LNC`, `NWC`, and `LNURL` do **not** support server-side lookup.
