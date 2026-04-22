# Dry-Run (Shadow) Mode

Shadow mode lets operators roll out L402 enforcement safely. With
`l402_dry_run on;` set on a location, the module evaluates the full pricing
pipeline, synthesises a valid L402 challenge, and records structured logs
and Prometheus metrics — but **always passes the request through to the
upstream**. No client ever sees `401` or `402`.

This is the recommended way to validate pricing, LN backend reachability,
and traffic patterns with real production traffic before flipping a route
to enforcement.

---

## Enabling shadow mode

```nginx
location /api/ {
    l402                        on;
    l402_amount_msat_default    10000;
    l402_dry_run                on;          # evaluate, log, never block
    proxy_pass                  http://upstream;
}
```

`l402_dry_run` accepts `on` or `off` (default). It can be combined with any
other `l402_*` directive — dynamic pricing from Redis, multi-tenant LNURLs,
macaroon timeouts, invoice rate limits — so the shadow-mode numbers you
measure match the configuration you are about to enforce.

`l402` must still be `on` for the module to enter the access handler.
Turning `l402` off disables the module entirely, including shadow mode.

---

## What happens per request

For every request reaching a shadow-mode location, the module:

1. Reads the static and dynamic (Redis) price for the route and picks the
   effective `amount_msat`.
2. Looks up any per-tenant LNURL override.
3. Verifies the `Authorization` header if one is present (L402 or Cashu).
4. If no valid token is present, calls the configured LN backend and
   generates a real invoice + macaroon — exactly the challenge enforce
   mode would have returned.
5. Emits a structured JSON log line and bumps the relevant Prometheus
   counters.
6. Returns `NGX_DECLINED`, so Nginx continues to the content phase and
   serves the upstream response with its natural status code.

> **Cost note**: generating a challenge contacts your LN backend on every
> unauthenticated request. If you have high traffic, start by enabling
> shadow mode on a sampled location (e.g. a canary route) before rolling
> it out everywhere.
>
> **Latency cap**: the challenge-synthesis call is bounded by a 5-second
> timeout. If the LN backend does not respond within that window the
> request still passes through (with no `X-L402-Dry-Run-Challenge`
> header) and `l402_dry_run_challenge_errors_total` is incremented —
> shadow mode must never add latency to user-facing traffic.

---

## Response headers

Shadow mode attaches debug headers to the upstream response so operators
can inspect what would have happened without scraping logs:

| Header | Meaning |
|---|---|
| `X-L402-Dry-Run: 1` | Marks the response as produced by shadow mode. Always present. |
| `X-L402-Dry-Run-Price-Msat: <n>` | Effective price for this route. Only emitted when the request *would* have been challenged (`402`) — not on paid-valid or rejected-invalid responses, to avoid leaking pricing against decided traffic. |
| `X-L402-Dry-Run-Challenge: L402 macaroon="...", invoice="..."` | The exact `WWW-Authenticate` value enforce mode would have returned. Only present when the request would have been challenged (`402`) and the LN backend produced an invoice. |
| `WWW-Authenticate: L402 macaroon="...", invoice="..."` | Also set alongside the challenge header, so real L402 clients can follow the payment flow in a staging environment. |
| `X-L402-Dry-Run-Rate-Limited: 1` + `X-L402-Dry-Run-Retry-After: <sec>` | Set when the request would have been challenged but hit `l402_invoice_rate_limit`. No invoice is generated and no challenge header is attached, mirroring what enforce mode would have done (429 + `Retry-After`). |

---

## Structured log events

Every shadow-mode request produces a single `info`-level JSON line via the
Rust logger. A minimal example (formatted for readability):

```json
{
  "event": "l402_dry_run",
  "route": "/api/resource",
  "price_msat": 10000,
  "price_source": "static",
  "backend": "LNURL",
  "client_ip": "203.0.113.42",
  "auth_state": "missing",
  "would_return": 402
}
```

Fields:

| Field | Values |
|---|---|
| `route` | Normalised request path used for pricing lookups. |
| `price_msat` | Effective price in millisatoshis. |
| `price_source` | `static` (from `nginx.conf`) or `dynamic` (from Redis). |
| `backend` | LN backend type snapshot: `LND`, `LNURL`, `NWC`, `CLN`, `BOLT12`, `ECLAIR`. |
| `client_ip` | From `X-Real-IP` → `X-Forwarded-For` → socket address. |
| `auth_state` | `missing`, `valid`, or `invalid`. |
| `would_return` | HTTP status enforce mode *would* have used (`200`, `401`, `402`). |
| `rate_limited` | `true` when `l402_invoice_rate_limit` would have produced a `429` — challenge synthesis was skipped to protect the LN backend. |

Pipe into `jq` to see a live firehose:

```bash
sudo tail -f /var/log/nginx/error.log \
  | grep '"event":"l402_dry_run"' \
  | jq -c 'select(.would_return != 200) | {route, price_msat, auth_state}'
```

---

## Prometheus metrics

The `l402_metrics` directive turns a location into a Prometheus scrape
endpoint. It serves counters in text exposition format v0.0.4.

```nginx
location = /metrics {
    l402_metrics;

    # Production: restrict to your scrape network.
    allow 10.0.0.0/8;
    deny  all;
}
```

Scrape it with a standard Prometheus config:

```yaml
scrape_configs:
  - job_name: ngx_l402
    metrics_path: /metrics
    static_configs:
      - targets: ['nginx:8000']
```

### Exported counters

| Metric | Meaning |
|---|---|
| `l402_requests_total` | Every request that entered the access handler with `l402 on;`. Incremented for both enforce and shadow traffic. |
| `l402_challenges_issued_total` | Requests that received a `402` response (enforce mode), counted *after* the rate-limit gate. |
| `l402_rate_limited_total` | Requests rejected with `429` by `l402_invoice_rate_limit` (enforce mode). |
| `l402_payments_valid_total` | Authorization headers that verified successfully (enforce mode only — dry-run traffic goes to `l402_dry_run_*`). |
| `l402_payments_invalid_total` | Authorization headers that failed verification (enforce mode only). |
| `l402_payments_missing_total` | Requests without an Authorization header (enforce mode only). |
| `l402_dry_run_requests_total` | Requests handled in shadow mode. |
| `l402_dry_run_would_block_total` | Shadow-mode requests that *would* have been blocked (`401` or `402`). |
| `l402_dry_run_would_allow_total` | Shadow-mode requests that *would* have been allowed (`200`). |
| `l402_dry_run_rate_limited_total` | Shadow-mode requests that would have hit `l402_invoice_rate_limit` — challenge synthesis was skipped. |
| `l402_dry_run_challenge_errors_total` | Shadow-mode requests where challenge synthesis failed (e.g. LN backend unreachable). |
| `l402_dry_run_price_msat_sum` | Sum of msat prices evaluated in shadow mode. Pair with `_requests_total` to derive an average price. |

### Useful PromQL

```promql
# Fraction of traffic that would be blocked if you flipped enforcement on:
rate(l402_dry_run_would_block_total[5m])
/
rate(l402_dry_run_requests_total[5m])

# Average price served by shadow mode (msat):
rate(l402_dry_run_price_msat_sum[5m])
/
rate(l402_dry_run_requests_total[5m])

# Challenge-synthesis error rate — a signal that your LN backend is flaky:
rate(l402_dry_run_challenge_errors_total[5m])
```

> The endpoint has no built-in authentication. Restrict it at the Nginx
> level with `allow`/`deny`, an auth subrequest, or a firewall rule —
> exposing it publicly leaks traffic volume and pricing details.

---

## Suggested rollout recipe

1. Deploy with `l402 on;` and `l402_dry_run on;` on the target location.
   Leave existing routes untouched.
2. Scrape `/metrics` for 24–48 hours. Confirm:
   - `l402_dry_run_challenge_errors_total` stays flat (LN backend healthy).
   - `l402_dry_run_would_allow_total / l402_dry_run_requests_total` matches
     the fraction of paying clients you expect.
   - `l402_dry_run_price_msat_sum` divided by request count matches your
     posted price.
3. Sample the JSON log for a few high-volume paths and confirm
   `price_source` is what you configured (`static` vs `dynamic`).
4. Remove `l402_dry_run on;` (or set it to `off`). Reload Nginx. The
   location now enforces.

If you ever need to revert, setting `l402_dry_run on;` again immediately
disables enforcement without touching upstream code paths.
