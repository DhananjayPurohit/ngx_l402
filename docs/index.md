# ngx_l402 — L402 Nginx Module

An [L402](https://docs.lightning.engineering/the-lightning-network/l402) authentication module for Nginx that enables Lightning Network-based monetization for your REST APIs (HTTP/1 and HTTP/2).

It supports the following Lightning backends:

| Backend | Description |
|---|---|
| **LND** | Lightning Network Daemon (direct gRPC) |
| **LNC** | Lightning Node Connect (remote LND via mailbox) |
| **CLN** | Core Lightning |
| **Eclair** | Eclair node |
| **LNURL** | Lightning Network URL |
| **NWC** | Nostr Wallet Connect |
| **BOLT12** | Reusable Lightning Offers |

The module can be configured to charge per unique API call, enabling per-endpoint monetization based on request paths.

![L402 module demo](https://github.com/user-attachments/assets/3db23ab0-6025-426e-86f8-3505fa0840b9)

---

## How It Works

```mermaid
graph TD;
    A[Request Received] --> B{Endpoint L402 Enabled?}
    B -->|No| C[Return 200 OK]
    B -->|Yes| D{"Any auth header present? (L402 or X-Cashu)"}
    D -->|No| F[Generate L402 Header macaroon & invoice]
    F --> G{Header Generation Success?}
    G -->|Yes| H[Add WWW-Authenticate Header]
    G -->|No| I[Return 500 Internal Server Error]
    H --> J[Return 402 Payment Required]
    D -->|Yes| K["Parse L402 macaroon/preimage or X-Cashu (if present)"]
    K --> L{Parse Success?}
    L -->|No| M[Return 500 Internal Server Error]
    L -->|Yes| N["Verify macaroon/preimage OR Cashu proofs"]
    N --> O{Verification Success?}
    O -->|Yes| P[Return 200 OK]
    O -->|No| Q[Return 401 Unauthorized]
```

---

## Quick Start

> **Note**: This module requires **NGINX version 1.28.0** or later.

The fastest way to get started is with Docker:

```bash
docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=LNURL \
  -e LNURL_ADDRESS=username@your-lnurl-server.com \
  -e ROOT_KEY=your-32-byte-hex-key \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

Then test it:

```bash
# Should return 200 OK
curl http://localhost:8000/

# Should return 402 Payment Required with L402 header
curl -i http://localhost:8000/protected
```

See the [Installation](./installation/manual.md) section for full setup options.
