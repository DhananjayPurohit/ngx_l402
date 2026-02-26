# L402 Protocol Notes

This module implements the [L402 protocol](https://docs.lightning.engineering/the-lightning-network/l402) using standard Lightning Network payments.

## Preimage Requirements

- **Only standard 32-byte (256-bit) Lightning preimages** are supported, as specified by the Lightning Network protocol.
- The preimage is verified against the `payment_hash` using SHA256 hashing.
- When a client provides an L402 authorization header, the preimage must be exactly 32 bytes.

> **⚠️ Wallet Compatibility**: Some wallets like [Wallet of Satoshi](https://www.walletofsatoshi.com/) provide 48-byte preimages (non-standard), which are **not compatible** with this module. Use wallets that provide standard 32-byte Lightning preimages.

## Authorization Header Format

The L402 authorization header is formatted as:

```
L402 <macaroon>:<preimage>
```

Or for Cashu eCash payments:

```
X-Cashu: <cashu-token>
```

## Payment Flow

1. Client makes a request to a protected endpoint
2. Server responds with `402 Payment Required` and a `WWW-Authenticate: L402` header containing a macaroon and a Lightning invoice
3. Client pays the invoice and obtains the preimage
4. Client retries the request with `Authorization: L402 <macaroon>:<preimage>`
5. Server verifies the macaroon and preimage, then serves the response
