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

## Eclair

```bash
Environment=LN_CLIENT_TYPE=ECLAIR
Environment=ECLAIR_ADDRESS=http://127.0.0.1:8282
Environment=ECLAIR_PASSWORD=eclairpass
Environment=ROOT_KEY=your-root-key
```

---

## Redis (Dynamic Pricing & Replay Protection)

```bash
Environment=REDIS_URL=redis://127.0.0.1:6379

# TTL for replay attack prevention (default: 86400 = 24 hours)
Environment=L402_PREIMAGE_TTL_SECONDS=86400
Environment=L402_CASHU_TOKEN_TTL_SECONDS=86400
```

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

## Logging

```bash
Environment=RUST_LOG=info
# For module-specific debug logs:
Environment=RUST_LOG=ngx_l402_lib=debug,info
```
