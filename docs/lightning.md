# Lightning Network Payments

ngx_l402 implements the [L402 protocol](https://docs.lightning.engineering/the-lightning-network/l402), enabling API monetization via **Lightning Network payments**. When a client hits a protected endpoint without a valid token, the module responds with `402 Payment Required` and a Lightning invoice. The client pays the invoice, receives a preimage, and presents it alongside the macaroon to gain access.

---

## Supported Backends

Configure the backend via the `LN_CLIENT_TYPE` environment variable:

| `LN_CLIENT_TYPE` | Description |
|---|---|
| `LND` | Lightning Network Daemon — direct gRPC connection |
| `LNC` | Lightning Node Connect — remote LND via mailbox (no open port needed) |
| `CLN` | Core Lightning |
| `ECLAIR` | Eclair node |
| `LNURL` | Lightning Network URL — delegate invoice generation to an LNURL server |
| `NWC` | Nostr Wallet Connect |
| `BOLT12` | Reusable Lightning Offers (BOLT12) |

See [Environment Variables](./config-env-vars.md) for the full list of per-backend settings.

---

## Payment Flow

1. Client requests a protected endpoint (no auth header).
2. Module generates a macaroon and requests an invoice from the configured Lightning backend.
3. Module responds `402 Payment Required` with:
   ```
   WWW-Authenticate: L402 macaroon="<macaroon>", invoice="<bolt11>"
   ```
4. Client pays the invoice and obtains the **preimage**.
5. Client retries with:
   ```
   Authorization: L402 <macaroon>:<preimage>
   ```
6. Module verifies the macaroon + preimage and returns `200 OK`.

---

## Authorization Header Format

```
Authorization: L402 <macaroon>:<preimage>
```

> The macaroon and preimage are separated by a colon (`:`). The preimage must be the **32-byte (256-bit) hex-encoded payment preimage** corresponding to the invoice's `payment_hash`.

---

## Wallet Compatibility

> [!WARNING]
> Some wallets (e.g. [Wallet of Satoshi](https://www.walletofsatoshi.com/)) return **48-byte non-standard preimages**, which are **not compatible** with this module. Use a wallet that returns a standard 32-byte preimage.

---

## Also Supported: Cashu eCash

In addition to Lightning, the module accepts **Cashu eCash tokens** via the `X-Cashu` header as an alternative payment method. See [Cashu eCash Support](./cashu.md) for details.
