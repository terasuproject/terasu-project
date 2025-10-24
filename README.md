# Terasu Project

A privacy-aware HTTP/HTTPS proxy with optional MITM interception, plus a cross‑platform Controller (CLI + GUI) to manage it.

- Proxy: Go, builds a small static binary; uses `github.com/fumiama/terasu` for TLS handshake tweaks and modern DNS (DoH/DoT)
- Controller: .NET/Avalonia; provides rules, certs, logs, traffic stats, diagnostics

## Layout
- `terasu/` — upstream library (TLS/DNS helpers)
- `terasu-proxy/` — proxy server exposing `/metrics` and `/logs` (SSE)
- `terasu-controller/` — controller
  - `terasu-controller-core/` — core logic
  - `terasu-controller-CLI/` — CLI
  - `terasu-controller-GUI/` — Avalonia GUI
- `docker-compose.yml` — one‑command local test setup

## Features
- Interception modes: `all` or `list` (domain allow‑list)
- Dynamic Root CA + per‑host certs for MITM
- DNS: system / DoH / DoT
- HTTP/1.1 + HTTP/2, CONNECT tunnels counted in metrics
- Metrics snapshot: `GET /metrics`
- Realtime logs (SSE): `GET /logs` with short backlog replay

## Quick start (Docker)
```bash
# from repo root
docker compose up -d --build

# tester generates HTTP/HTTPS traffic via the proxy
docker logs terasu-proxy-tester

# metrics snapshot
curl http://localhost:9090/metrics

# realtime logs (SSE)
curl -N http://localhost:9090/logs
```
Default ports: proxy `8080`, metrics/logs `9090`.

## Proxy config (example)
Path in container: `/etc/terasu-proxy/config.yaml`
```yaml
listen: 0.0.0.0:8080
metricsAddr: 0.0.0.0:9090
intercept:
  mode: all          # all | list
  domains:
    - example.com    # used when mode=list

dns:
  mode: system       # system | doh | dot
  # doh: https://cloudflare-dns.com/dns-query
  # dot: 1.1.1.1:853

# auth:
#   username: user
#   password: pass
```
Env overrides: `TERASU_PROXY_DNS_MODE`, `TERASU_PROXY_METRICS_ADDR`.

CA: generated at `/data/ca.pem` (Docker volume). Install into client trust store for HTTPS interception.

## Build locally
Proxy (Go 1.24):
```bash
cd terasu-proxy
CGO_ENABLED=0 go build -ldflags="-s -w -checklinkname=0" -o terasu-proxy ./cmd/terasu-proxy
```
Controller (.NET 9):
```bash
# GUI
cd terasu-controller/terasu-controller-GUI
dotnet run
# CLI
cd ../terasu-controller-CLI
dotnet run -- --help
```
Docker all‑in‑one:
```bash
docker compose up -d --build
```

## Troubleshooting
- GUI logs empty: ensure proxy metrics base is reachable (default `http://127.0.0.1:9090`) and generate traffic.
- HTTPS cert errors: install `/data/ca.pem` or disable interception for those hosts.
- Minimal tester image may not update trust store; it still exercises proxy paths/metrics.

## License
- Root: `UNLICENSE`
- `terasu/` retains its own `LICENSE`
