# macOS Local Setup Guide

This guide is for contributors running `ngx_l402` locally on macOS.

## 1. Prerequisites

Docker is the only requirement. Make sure the Docker daemon is running before continuing.

## 2. Clone and enter the repository

```bash
git clone https://github.com/DhananjayPurohit/ngx_l402.git
cd ngx_l402
```

## 3. Start the stack

The first run compiles the module inside a Linux container (multi-stage Dockerfile), so it will take a few minutes. Subsequent runs use the Docker build cache.

```bash
ROOT_KEY=$(openssl rand -hex 32) \
CASHU_WALLET_SECRET=$(openssl rand -hex 32) \
docker compose up -d bitcoind lndnode-receiver redis nginx-lnd
```

## 4. Verify

```bash
curl -i http://localhost:8000/protected
```

Expected: `402 Payment Required` with a `WWW-Authenticate: L402 ...` header.

## 5. Useful commands

```bash
docker compose ps                    # container status
docker logs nginx-lnd -f             # nginx logs
docker compose down                  # stop stack
```
