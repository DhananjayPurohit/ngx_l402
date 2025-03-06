# L402 Nginx Module

This project implements an L402 authentication module for Nginx that enables Lightning Network-based API monetization. The module supports both LNURL and LND backends for payment processing.

## Installation & Usage

1. Copy the module file `libngx_l402_lib.so` to your Nginx modules directory (typically `/etc/nginx/modules/`)

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

5. Restart Nginx:
```bash
nginx -s reload
```
