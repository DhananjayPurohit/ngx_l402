# Building from Source

## Prerequisites

Install required system dependencies:

```bash
sudo apt-get install -y \
  build-essential \
  clang \
  libclang-dev \
  libc6-dev \
  zlib1g-dev \
  pkg-config \
  libssl-dev \
  protobuf-compiler \
  nginx
```

Install Rust and Cargo:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

## Build Steps

1. Clone the repository:

```bash
git clone https://github.com/DhananjayPurohit/ngx_l402.git
cd ngx_l402
```

2. Download Nginx source and build the module:

> ⚠️ **Important**: You must download the exact Nginx source code matching your target version and set the `NGINX_SOURCE_DIR` environment variable before building.

```bash
# Example for Nginx 1.28.0
curl -fsSL http://nginx.org/download/nginx-1.28.0.tar.gz -o nginx.tar.gz
tar -xzf nginx.tar.gz
export NGINX_SOURCE_DIR=$(pwd)/nginx-1.28.0

cargo build --release --features export-modules
```

The compiled module will be at `target/release/libngx_l402_lib.so`.

3. Copy to your Nginx modules directory:

```bash
sudo cp target/release/libngx_l402_lib.so /etc/nginx/modules/
```

4. Follow the remaining [manual installation steps](./install-manual.md).
