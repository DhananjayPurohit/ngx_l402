# Docker Installation

The easiest way to deploy the L402 Nginx module is with our official Docker images.

```bash
docker pull ghcr.io/dhananjaypurohit/ngx_l402:latest
```

---

## Quick Start Examples

### 1. LNURL Backend (Simplest Setup)

```bash
docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=LNURL \
  -e LNURL_ADDRESS=username@your-lnurl-server.com \
  -e ROOT_KEY=your-32-byte-hex-key \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

### 2. LND Backend with Cashu Support

```bash
mkdir -p ~/l402-data
cp ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon ~/l402-data/
cp ~/.lnd/tls.cert ~/l402-data/

docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=LND \
  -e LND_ADDRESS=your-lnd-ip:10009 \
  -e MACAROON_FILE_PATH=/app/data/admin.macaroon \
  -e CERT_FILE_PATH=/app/data/tls.cert \
  -e CASHU_ECASH_SUPPORT=true \
  -e CASHU_WALLET_SECRET=your-32-byte-hex-secret \
  -e CASHU_DB_PATH=/app/data/cashu_tokens.db \
  -e CASHU_WHITELISTED_MINTS=https://mint1.example.com,https://mint2.example.com \
  -e CASHU_REDEEM_ON_LIGHTNING=true \
  -e REDIS_URL=redis://redis:6379 \
  -v ~/l402-data:/app/data \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

### 3. LND via Lightning Node Connect (LNC)

```bash
# Generate a pairing phrase from Lightning Terminal first:
# litcli sessions add --label="nginx-l402" --type=admin

docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=LND \
  -e LNC_PAIRING_PHRASE="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10" \
  -e LNC_MAILBOX_SERVER=mailbox.terminal.lightning.today:443 \
  -e ROOT_KEY=your-32-byte-hex-key \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

### 4. CLN Backend (Core Lightning)

```bash
docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=CLN \
  -e CLN_LIGHTNING_RPC_FILE_PATH=/app/data/lightning-rpc \
  -e ROOT_KEY=your-32-byte-hex-key \
  -e CASHU_ECASH_SUPPORT=true \
  -e CASHU_WALLET_SECRET=your-32-byte-hex-secret \
  -e CASHU_DB_PATH=/app/data/cashu_tokens.db \
  -v ~/.lightning/bitcoin/lightning-rpc:/app/data/lightning-rpc:ro \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

### 5. NWC Backend (Nostr Wallet Connect)

```bash
docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=NWC \
  -e NWC_URI=nostr+walletconnect://your-pubkey?relay=wss://relay.damus.io&secret=your-secret \
  -e ROOT_KEY=your-32-byte-hex-key \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

### 6. High-Performance P2PK Mode (Recommended for Production)

```bash
docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=LND \
  -e LND_ADDRESS=your-lnd-ip:10009 \
  -e MACAROON_FILE_PATH=/app/data/admin.macaroon \
  -e CERT_FILE_PATH=/app/data/tls.cert \
  -e CASHU_ECASH_SUPPORT=true \
  -e CASHU_P2PK_MODE=true \
  -e CASHU_P2PK_PRIVATE_KEY=your-32-byte-hex-private-key \
  -e CASHU_WALLET_SECRET=your-32-byte-hex-secret \
  -e CASHU_DB_PATH=/app/data/cashu_tokens.db \
  -e CASHU_WHITELISTED_MINTS=https://mint1.example.com \
  -e CASHU_REDEEM_ON_LIGHTNING=true \
  -e REDIS_URL=redis://redis:6379 \
  -v ~/l402-data:/app/data \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

### 7. BOLT12 Backend (Reusable Offers)

```bash
docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=BOLT12 \
  -e BOLT12_OFFER=lno1... \
  -e CLN_LIGHTNING_RPC_FILE_PATH=/app/data/lightning-rpc \
  -e ROOT_KEY=your-32-byte-hex-key \
  -v ~/.lightning/bitcoin/lightning-rpc:/app/data/lightning-rpc:ro \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

### 8. Eclair Backend

```bash
docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=ECLAIR \
  -e ECLAIR_ADDRESS=http://your-eclair-node:8282 \
  -e ECLAIR_PASSWORD=your-eclair-password \
  -e ROOT_KEY=your-32-byte-hex-key \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

---

## Generating Required Secrets

```bash
# ROOT_KEY (required for all setups)
openssl rand -hex 32

# CASHU_WALLET_SECRET (for Cashu support)
openssl rand -hex 32

# CASHU_P2PK_PRIVATE_KEY (for P2PK mode)
openssl rand -hex 32
```

---

## Testing Your Setup

```bash
# Test free endpoint
curl http://localhost:8000/

# Test protected endpoint (should return 402 with L402 header)
curl -i http://localhost:8000/protected

# Check container logs
docker logs l402-nginx -f

# Stop the container
docker stop l402-nginx
```

---

## Specific Versions

```bash
docker pull ghcr.io/dhananjaypurohit/ngx_l402:v1.2.3
```
