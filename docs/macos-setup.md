# macOS Local Setup Guide (Docker NGINX)

This guide is for contributors running `ngx_l402` locally on macOS.

## 1. Prerequisites

Install required tools:

```bash
brew install rustup-init protobuf docker docker-compose
```

Install and activate Rust:

```bash
rustup-init -y
source "$HOME/.cargo/env"
rustup default stable
```

Start Docker Desktop before continuing.

## 2. Clone and enter the repository

```bash
git clone https://github.com/DhananjayPurohit/ngx_l402.git
cd ngx_l402
```

## 3. Build and test locally (optional, for IDE / linting)

These commands verify that the Rust code compiles on your machine and are useful for IDE integration, but are **not required** for running nginx — Docker handles the Linux build automatically.

```bash
cargo build --release --features export-modules
cargo test
```

Optional gRPC example tests:

```bash
cargo test --manifest-path grpc-server/Cargo.toml
```

## 4. Start local LND + Docker nginx

The first `docker compose up` compiles the module inside a Linux container (multi-stage Dockerfile), so it will take a few minutes on the first run. Subsequent runs use the Docker build cache.

If Homebrew nginx is using port `8000`, stop it first:

```bash
brew services stop nginx
```

Start the stack (LND backend + nginx):

```bash
ROOT_KEY=$(openssl rand -hex 32) \
CASHU_WALLET_SECRET=$(openssl rand -hex 32) \
docker compose up -d bitcoind lndnode-receiver redis nginx-lnd
```

Check container status:

```bash
docker compose ps nginx-lnd lndnode-receiver bitcoind redis
```

## 5. Verify L402 challenge

```bash
curl -i http://localhost:8000/protected
```

Expected result: `402 Payment Required` and a `WWW-Authenticate: L402 ...` header.

## 6. Useful commands

Logs:

```bash
docker logs nginx-lnd -f
docker logs lndnode-receiver -f
```

Stop stack:

```bash
docker compose down
```

## 7. Optional Homebrew nginx path

If you specifically want to run the module in Homebrew nginx, use the manual path in `README.md`. For regular contributor setup and local testing on macOS, use Docker nginx.
