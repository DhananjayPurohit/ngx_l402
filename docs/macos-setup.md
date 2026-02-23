# macOS Local Setup Guide

This guide is for contributors running `ngx_l402` locally on macOS.

## 1. Prerequisites

Install Xcode command line tools:

```bash
xcode-select --install
```

Install required dependencies with Homebrew:

```bash
brew install rustup-init openssl@3 protobuf nginx pkg-config
```

Install and activate Rust toolchain:

```bash
rustup-init -y
source "$HOME/.cargo/env"
rustup default stable
```

## 2. Clone and enter the repository

```bash
git clone https://github.com/DhananjayPurohit/ngx_l402.git
cd ngx_l402
```

## 3. Build locally on macOS

```bash
cargo build --release --features export-modules
```

Expected output file:

```bash
target/release/libngx_l402_lib.dylib
```

## 4. Run tests locally on macOS

Module crate test command:

```bash
cargo test
```

Optional gRPC example tests:

```bash
cargo test --manifest-path grpc-server/Cargo.toml
```

Notes:
- The first run requires internet access to download crates.
- `grpc-server` has its own dependency graph and may need an initial online fetch.

## 5. Install module into Homebrew NGINX

Create module directory and copy the built module:

```bash
mkdir -p "$(brew --prefix)/lib/nginx/modules"
cp target/release/libngx_l402_lib.dylib "$(brew --prefix)/lib/nginx/modules/libngx_l402_lib.so"
```

Find your Homebrew prefix:

```bash
brew --prefix
```

Then add this line near the top of your NGINX config (`<brew-prefix>/etc/nginx/nginx.conf`):

```nginx
load_module /opt/homebrew/lib/nginx/modules/libngx_l402_lib.so;
```

Then validate and restart:

```bash
nginx -t
brew services restart nginx
```

## 6. Minimal local runtime env

Set at least these environment variables before starting NGINX with this module:

```bash
export LN_CLIENT_TYPE=LNURL
export LNURL_ADDRESS="user@your-lnurl-domain"
export ROOT_KEY="$(openssl rand -hex 32)"
```

Optional, but recommended for dynamic pricing and replay protection:

```bash
export REDIS_URL=redis://127.0.0.1:6379
```

## 7. Quick local checks

```bash
curl -i http://localhost:8000/protected
```

A protected route should return `402 Payment Required` with an `WWW-Authenticate` L402 header when payment is not yet provided.
