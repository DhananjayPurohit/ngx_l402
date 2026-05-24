# Capability Manifest

The `l402_manifest` directive turns a location into a discovery endpoint
that emits a JSON description of every L402-protected route on the
server. It is intended to live at `/.well-known/l402-services` ([RFC 8615][well-known]),
making this instance self-describing to clients that have only the host.

```nginx
location = /.well-known/l402-services {
    l402_manifest;

    # Optional: restrict who can scrape pricing details.
    # allow 10.0.0.0/8;
    # deny  all;
}
```

This is the agent-era equivalent of `robots.txt` or `security.txt`. An
autonomous agent (or any client) given only `https://example.com` can
fetch the manifest, learn which routes are paid, how much they cost, and
which payment backends are accepted — without any out-of-band integration.

---

## Example response

```json
{
  "version": "1",
  "service": {
    "name": "Example API",
    "description": "Stock data API"
  },
  "payment_methods": [
    {
      "type": "lightning",
      "backend": "LNURL",
      "address": "hello@getalby.com"
    },
    {
      "type": "cashu",
      "mints": ["https://mint.minibits.cash"],
      "p2pk_supported": true,
      "challenge_header": "X-Cashu"
    }
  ],
  "routes": [
    {
      "path": "/protected",
      "price": {
        "type": "static",
        "amount_msat": 10000
      },
      "caveats_required": ["RequestPath = /protected"]
    },
    {
      "path": "/rate-limited",
      "price": {
        "type": "static",
        "amount_msat": 10000
      },
      "caveats_required": ["RequestPath = /rate-limited"],
      "rate_limit": {
        "max_requests": 2,
        "window_secs": 60
      }
    }
  ]
}
```

---

## What the manifest describes

| Field | Source | Meaning |
|---|---|---|
| `version` | constant `"1"` | Schema version. Bumped on breaking changes; agents should reject unknown majors. |
| `service.name`, `service.description`, `service.operator`, `service.contact` | env vars `L402_SERVICE_NAME`, `L402_SERVICE_DESCRIPTION`, `L402_SERVICE_OPERATOR`, `L402_SERVICE_CONTACT` | Optional, omitted when unset. |
| `payment_methods[].type` | `lightning` or `cashu` | Which payment rail this method describes. |
| `payment_methods[].backend` | env var `LN_CLIENT_TYPE` | `LNURL`, `LND`, `CLN`, `NWC`, `BOLT12`, `ECLAIR`, `LNC`. |
| `payment_methods[].address` | env var `LNURL_ADDRESS` (LNURL backends only) | Server-default LN address. May be overridden per-route via `lnurl_addr`. |
| `payment_methods[].mints` | env var `CASHU_WHITELISTED_MINTS` | Allowed Cashu mints (when Cashu is enabled). |
| `payment_methods[].p2pk_supported` | env var `CASHU_P2PK_MODE` | Whether NUT-24 P2PK Cashu is enabled. |
| `routes[].path` | `location` directive | URL path served by this route. |
| `routes[].price.amount_msat` | `l402_amount_msat_default` | Base price after `merge_loc_conf`. |
| `routes[].caveats_required` | derived | Caveats the issued macaroon will carry. Today always `[RequestPath = <path>]`. |
| `routes[].macaroon_timeout_secs` | `l402_macaroon_timeout` | Omitted when `0` (no expiry). |
| `routes[].lnurl_addr` | `l402_lnurl_addr` | Per-route LNURL override for multi-tenant deployments. |
| `routes[].rate_limit` | `l402_invoice_rate_limit` | Server-side invoice rate limit applied before challenge issuance. |
| `routes[].auto_detect_payment` | `l402_auto_detect_payment` | When true, clients can omit the preimage and the server settles via node lookup. |

Dynamic (Redis-backed) pricing is **not** reflected in `price.amount_msat` —
the manifest emits the static default. Dynamic prices change per request
and would require a Redis round-trip per route to render accurately;
that's out of scope for v1.

---

## Hiding a route

Operators may want certain paid routes to remain undiscoverable — private
APIs, beta tiers, customer-specific endpoints. Use `l402_manifest_hide;`
on the location:

```nginx
location /internal-paid {
    l402 on;
    l402_amount_msat_default 100000;
    l402_manifest_hide;       # not advertised in /.well-known/l402-services
}
```

The route still enforces L402 normally. It just doesn't appear in the
manifest's `routes[]` array.

---

## Service-level metadata

The optional `service` block is read from environment variables at
manifest-render time:

```sh
L402_SERVICE_NAME="Example API"
L402_SERVICE_DESCRIPTION="Premium financial data, paid per request."
L402_SERVICE_OPERATOR="npub1abcd..."   # Nostr pubkey, DID, or free-form
L402_SERVICE_CONTACT="ops@example.com"
```

All four are optional. Unset variables are omitted from the response so
the manifest stays valid JSON even with no service metadata.

---

## Caveats and limitations

- **Per-worker registry.** Like `l402_metrics`, the manifest registry is
  per-nginx-worker. On a multi-worker deployment, every worker sees the
  same routes (config is shared), so this is a non-issue for the manifest
  itself.
- **No authentication by default.** Pricing information is public.
  Restrict the endpoint with `allow`/`deny`, an auth subrequest, or a
  firewall if competitors should not see your full pricing matrix.
- **Reload behaviour.** On `nginx -s reload`, new workers start with a
  fresh registry built from the new config. Old workers serve in-flight
  requests with their existing registry until they exit.

---

## Why this matters

Without a manifest, every L402 integration is a bespoke wiring job: the
client must be told the routes, prices, payment backends, and caveat
formats out of band. With one, an agent can land on a host and onboard
itself end-to-end:

```text
GET /.well-known/l402-services  → learn the API surface
GET /protected                → receive 402 + bolt11 invoice
PAY the invoice               → get preimage
GET /protected with L402 auth → success
```

For autonomous agents — Claude tools, MCP servers, custom-built — this is
the difference between L402 being a protocol and L402 being a
*discoverable web standard*.

[well-known]: https://datatracker.ietf.org/doc/html/rfc8615
