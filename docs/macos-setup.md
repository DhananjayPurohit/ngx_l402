# macOS Local Setup Guide

This guide is for contributors running `ngx_l402` locally on macOS.

## 1. Prerequisites

- **Docker** — make sure the Docker daemon is running.
- **Rust** — install via [rustup](https://rustup.rs) if not already present:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

## 2. Clone and enter the repository

```bash
git clone https://github.com/DhananjayPurohit/ngx_l402.git
cd ngx_l402
```

## 3. Start the stack

Copy the example env file and start the services:

```bash
cp .env.example .env
docker compose up -d bitcoind lndnode-receiver redis grpc-content-server nginx-lnd
```

The first run compiles the module inside a Linux container (multi-stage Dockerfile), so it will take a few minutes. Subsequent runs use the Docker build cache.

Fund the regtest LND node so it can create invoices:

```bash
docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass createwallet miner 2>/dev/null
docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=miner generatetoaddress 101 \
  $(docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass -rpcwallet=miner getnewaddress) > /dev/null
sleep 5
```

## 4. Verify

```bash
curl -i http://localhost:8000/protected
```

Expected: `402 Payment Required` with a `WWW-Authenticate: L402 ...` header. If the request hangs, wait a few seconds for LND to finish syncing and try again.

## 5. Development workflow

After editing the Rust source, rebuild and restart nginx:

```bash
docker compose build nginx-lnd && docker compose up -d nginx-lnd
```

Dependencies are cached, so only the module recompiles (~20 seconds).

You can also run `cargo check` locally for fast feedback from your editor without rebuilding the container.

## 6. Useful commands

```bash
docker compose ps                    # container status
docker logs nginx-lnd -f             # nginx logs
docker compose down                  # stop stack
```
