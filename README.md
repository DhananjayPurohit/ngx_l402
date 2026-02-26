# ngx_l402 — L402 Nginx Module

An [L402](https://docs.lightning.engineering/the-lightning-network/l402) authentication module for Nginx that enables Lightning Network-based monetization for your REST APIs (HTTP/1 and HTTP/2).

Supports **LND**, **LNC**, **CLN**, **Eclair**, **LNURL**, **NWC**, and **BOLT12** backends.

![L402 module demo](https://github.com/user-attachments/assets/3db23ab0-6025-426e-86f8-3505fa0840b9)

---

## 📖 Documentation

**Full documentation is available at: https://dhananjaypurohit.github.io/ngx_l402/**

- [Installation](https://dhananjaypurohit.github.io/ngx_l402/installation/manual.html)
- [Docker Setup](https://dhananjaypurohit.github.io/ngx_l402/installation/docker.html)
- [Configuration & Environment Variables](https://dhananjaypurohit.github.io/ngx_l402/configuration/env-vars.html)
- [Cashu eCash Support](https://dhananjaypurohit.github.io/ngx_l402/cashu.html)
- [Multi-Tenant](https://dhananjaypurohit.github.io/ngx_l402/configuration/multi-tenant.html)
- [Building from Source](https://dhananjaypurohit.github.io/ngx_l402/advanced/building.html)

---

## ⚡ Quick Start

> Requires **NGINX 1.28.0** or later.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENCE)
