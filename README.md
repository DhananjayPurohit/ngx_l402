# L402 Nginx Module

This project implements an L402 authentication module for Nginx that enables Lightning Network-based API monetization. The module supports both LNURL and LND backends for payment processing.

## Installation & Usage

1. Download the module file `libngx_l402_lib.so` from the [latest release](https://github.com/DhananjayPurohit/ngx_l402/releases/latest) and copy it to your Nginx modules directory (typically `/etc/nginx/modules/`)

2. Enable the module in your nginx.conf:

```nginx
load_module /etc/nginx/modules/libngx_l402_lib.so;
``` 

3. Enable L402 for specific locations:

```nginx
location /protected {
    root   /usr/share/nginx/html;
    index  index.html index.htm;
    
    # l402 module directive:   
    l402 on;
}
```

4. Set the following environment variables:

if using LNURL:
```bash
export LN_CLIENT_TYPE=LNURL
export LNURL_ADDRESS=
# Root key for minting macaroons
export ROOT_KEY=
export CURRENCY=USD
export AMOUNT=0.01
```

if using LND:
```bash
export LN_CLIENT_TYPE=LND
export LND_ADDRESS=
export MACAROON_FILE_PATH=
export CERT_FILE_PATH=
# Root key for minting macaroons
export ROOT_KEY=
export CURRENCY=USD
export AMOUNT=0.01
```

if using NWC:
```bash
export LN_CLIENT_TYPE=NWC
export NWC_URI=
# Root key for minting macaroons
export ROOT_KEY=
export CURRENCY=USD
export AMOUNT=0.01
```

5. Restart Nginx:
```bash
nginx -s reload
```

## Building from Source

To build the module from source:

1. Install Rust and Cargo if not already installed:

2. Clone the repository:

```bash
git clone https://github.com/DhananjayPurohit/ngx_l402.git
cd ngx_l402
```

3. Build the module:

```bash
cargo build --release --features export-modules
```

4. Copy the module file `libngx_l402_lib.so` to your Nginx modules directory (typically `/etc/nginx/modules/`)

```bash
cp target/release/libngx_l402_lib.so /etc/nginx/modules/
```


