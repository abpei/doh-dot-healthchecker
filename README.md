# DOH/DOT Health Checker

A Docker container that monitors DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) endpoints. It periodically probes configured targets, validates DNS responses against expected values, and sends email alerts when servers fail or recover.

## Features

- **DoH probing**: JSON API with automatic wireformat POST fallback (for Pi-hole and other implementations that only support wireformat)
- **DoT probing**: TLS socket with 2-byte length-prefixed DNS messages per RFC 7858
- **Threshold-based alerting**: Configurable consecutive failure/success thresholds before triggering alerts
- **SMTP with STARTTLS**: Alert and recovery emails with graceful error handling
- **Unbuffered logging**: All probe results to stdout with timestamps for `docker logs` visibility

## Quick Start

```bash
cp .env.example .env
# Edit .env with your actual targets, domains, and SMTP credentials

docker compose up -d
docker compose logs -f
```

## Environment Variables

| Variable | Required | Default | Example | Description |
|---|---|---|---|---|
| `TARGETS` | Yes | — | `https://dns.google/dns-query,1.1.1.1:853` | Comma-separated server list. `https://` prefix = DoH, anything else = DoT (host:port or host with default port 853) |
| `TEST_DOMAINS` | Yes | — | `google.com\|142.250.80.46,cloudflare.com\|104.16.132.229` | Comma-separated `domain\|expected_A_record` pairs |
| `SMTP_HOST` | Yes | — | `smtp.example.com` | SMTP server hostname |
| `SMTP_PORT` | Yes | — | `587` | SMTP port (STARTTLS) |
| `SMTP_USER` | Yes | — | `user@example.com` | SMTP username |
| `SMTP_PASS` | Yes | — | `***` | SMTP password |
| `SMTP_FROM` | Yes | — | `doh-monitor@example.com` | Sender email address |
| `SMTP_TO` | Yes | — | `admin@example.com` | Recipient email address |
| `PROBE_INTERVAL` | No | `300` | `60` | Seconds between probe cycles |
| `FAILURE_THRESHOLD` | No | `5` | `3` | Consecutive failures before sending alert email |
| `RECOVERY_THRESHOLD` | No | `3` | `2` | Consecutive successes before sending recovery email |
| `DNS_SERVER` | No | `1.1.1.1` | `8.8.8.8` | Fallback DNS for resolving DoT hostnames and PTR lookups |
| `DOT_HOSTNAME` | No | — | `dns1.example.com` | Explicit override for the TLS SNI hostname on DoT connections. When set, takes priority over automatic PTR lookup. Only needed if the PTR-derived name is wrong or the server expects a different hostname |
| `DOT_VERIFY_HOSTNAME` | No | `true` | `false` | Set to `false` to disable TLS hostname verification on DoT connections. Only use when the target uses a self-signed or otherwise unverifiable certificate |

## Log Format

```
[2026-06-19 19:30:00] OK   https://dns.google/dns-query -> google.com (142.250.80.46) 45ms
[2026-06-19 19:30:00] FAIL https://dns.google/dns-query -> google.com TIMEOUT
[2026-06-19 19:30:00] Starting DOH healthchecker — 2 target(s), 2 domain(s), probe interval 300s
[2026-06-19 19:30:00] Shutting down (received Ctrl+C)
```

## Project Structure

```
doh-healthchecker/
├── main.py              # Entry point: probe loop, env config, logging
├── dns_probe.py         # DoH and DoT probing logic
├── alerting.py          # AlertManager and ProbeState for threshold tracking
├── Dockerfile           # python:3.13-slim based
├── docker-compose.yml   # Compose configuration
├── requirements.txt     # Python dependencies
├── .env.example         # Template environment file
└── README.md            # This file
```

## Testing

```bash
pip install pytest
pytest -v
```

## Architecture

1. **main.py** loads environment variables, parses targets/domains, and runs the infinite probe loop
2. **dns_probe.py** provides `probe_doh()` and `probe_dot()` functions that return `{success, actual_ip, response_time_ms, error}` dicts
3. **alerting.py** tracks per-(target, domain) state via `ProbeState` and sends emails via `AlertManager` when thresholds are crossed

The probe loop catches all exceptions per-target — a single server failure never crashes the container.

### Automatic PTR Lookup for DoT

When a DoT target is a raw IP address (e.g. `188.245.192.196:853`), the checker automatically performs a PTR (reverse DNS) lookup to discover the hostname the server's TLS certificate is likely issued for. The resolution order for TLS SNI is:

1. **`DOT_HOSTNAME` env var** — explicit override, highest priority
2. **PTR lookup** — automatic reverse DNS on the target IP
3. **Raw IP** — fallback (cert verification may fail unless `DOT_VERIFY_HOSTNAME=false`)

PTR results are cached at startup so each target is resolved once, not on every probe cycle. This means adding a raw IP DoT target "just works" — no `DOT_HOSTNAME` needed in most cases.
