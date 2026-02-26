# Logging

## View Logs

### systemd / Manual Install

```bash
# Module initialization and system logs
sudo journalctl -u nginx

# Nginx error logs (real-time)
sudo tail -f /var/log/nginx/error.log

# Cashu redemption logs
sudo tail -f /var/log/nginx/cashu_redemption.log
```

### Docker

```bash
docker logs l402-nginx -f
```

---

## Log Levels

Control verbosity via the `RUST_LOG` environment variable:

```bash
# Standard info logs (recommended for production)
Environment=RUST_LOG=info

# Detailed debug logs for all modules
Environment=RUST_LOG=debug

# Module-specific debug logs only (reduces noise)
Environment=RUST_LOG=ngx_l402_lib=debug,info
```
