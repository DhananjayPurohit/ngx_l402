# ngx_l402 — L402 Nginx Module

An [L402](https://docs.lightning.engineering/the-lightning-network/l402) authentication module for Nginx that enables Lightning Network-based monetization for your REST APIs (HTTP/1 and HTTP/2).

Supports **LND**, **LNC**, **CLN**, **Eclair**, **LNURL**, **NWC**, and **BOLT12** backends.

For local contributor setup on macOS (Docker nginx recommended), see `docs/macos-setup.md`.

![L402 module demo](https://github.com/user-attachments/assets/3db23ab0-6025-426e-86f8-3505fa0840b9)

---

## 📖 Documentation

**Full documentation is available at: https://dhananjaypurohit.github.io/ngx_l402/**

- [Installation](https://dhananjaypurohit.github.io/ngx_l402/install-manual.html)
- [Docker Setup](https://dhananjaypurohit.github.io/ngx_l402/install-docker.html)
- [Configuration & Environment Variables](https://dhananjaypurohit.github.io/ngx_l402/config-env-vars.html)
- [Cashu eCash Support](https://dhananjaypurohit.github.io/ngx_l402/cashu.html)
- [Multi-Tenant](https://dhananjaypurohit.github.io/ngx_l402/config-multi-tenant.html)
- [Building from Source](https://dhananjaypurohit.github.io/ngx_l402/building.html)

---

## ⚡ Quick Start

> Requires **NGINX 1.28.0** or later.
>
> Pre-built binaries are provided for **NGINX 1.28.0** only. For other versions, build from source:
> ```
> docker build --build-arg NGX_VERSION=<your-version> -t ngx_l402 .
> ```

```bash
docker run -d \
  --name l402-nginx \
  -p 8000:8000 \
  -e LN_CLIENT_TYPE=LNURL \
  -e LNURL_ADDRESS=username@your-lnurl-server.com \
  -e ROOT_KEY=$(openssl rand -hex 32) \
  ghcr.io/dhananjaypurohit/ngx_l402:latest
```

Test it:

```bash
curl http://localhost:8000/           # 200 OK
curl -i http://localhost:8000/protected  # 402 Payment Required
```

---

## Shadow mode (safe rollouts)

Before switching a route to enforced L402 in production, you can run it in
**shadow mode** to validate pricing, LN backend reachability, and traffic
patterns *without* blocking any requests:

```nginx
location /api/ {
    l402                        on;
    l402_amount_msat_default    10000;
    l402_dry_run                on;      # evaluate, log, never block
    proxy_pass                  http://upstream;
}

location = /metrics {
    l402_metrics;                         # Prometheus scrape endpoint
}
```

In shadow mode the module:

- Evaluates the full pricing pipeline (static config + Redis overrides).
- Attempts to synthesise a valid L402 challenge and exposes it via the
  `X-L402-Dry-Run-Challenge` response header.
- Emits one structured JSON log line per request (route, price, backend,
  client IP, auth state, would-be status).
- Updates `l402_dry_run_*` Prometheus counters.
- **Always returns 200 OK to the client.**

See [`nginx.conf`](nginx.conf) for a worked example.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENCE)
