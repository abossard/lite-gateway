# Lite Gateway

[![Docker Build & Test](https://github.com/abossard/lite-gateway/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/abossard/lite-gateway/actions/workflows/docker-publish.yml)
[![Release](https://github.com/abossard/lite-gateway/actions/workflows/release-yarp.yml/badge.svg)](https://github.com/abossard/lite-gateway/actions/workflows/release-yarp.yml)
[![GHCR Version](https://ghcr-badge.egpl.dev/abossard/lite-gateway/latest_tag?trim=major&label=ghcr.io)](https://github.com/abossard/lite-gateway/pkgs/container/lite-gateway)
[![Image Size](https://ghcr-badge.egpl.dev/abossard/lite-gateway/size)](https://github.com/abossard/lite-gateway/pkgs/container/lite-gateway)
![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)
![YARP](https://img.shields.io/badge/YARP-2.3.0-blue)
![Native AOT](https://img.shields.io/badge/Native_AOT-✓-brightgreen)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macOS-lightgrey)

A lightweight reverse proxy built on [YARP](https://microsoft.github.io/reverse-proxy/)
that forwards a specific HTTP header on every request. Built with .NET 10 and Native AOT
for a single-file, zero-dependency binary.

```
Client ──▶ Lite Gateway (YARP) ──▶ Backend
             injects X-Custom-Header
```

## Why YARP?

[YARP (Yet Another Reverse Proxy)](https://microsoft.github.io/reverse-proxy/) is
Microsoft's production-grade reverse proxy toolkit. It gives us:

- **Declarative config** — routes, clusters, and header transforms in a single JSON file
- **Hot-reload** — edit the config while the proxy is running, no restart needed
- **Native AOT** — compiles to a single ~15 MB binary with sub-millisecond startup
- **Battle-tested** — powers Azure, M365, and other Microsoft services at scale

## Quick Start

### Option A: Docker Compose (recommended)

```bash
docker compose up --build
```

This starts an echo backend and the YARP gateway. Test it:

```bash
curl -s http://localhost:8080/ | jq .headers
```

You'll see `X-Custom-Header: my-value` in the response headers — injected by the gateway.

### Option B: Run from source

```bash
dotnet run --project src/LiteGateway.YarpProxy
```

The proxy starts on `http://localhost:8080` and reads `config.json` from the working
directory (or use `--config /path/to/config.json`).

### Option C: Pull from GitHub Container Registry

```bash
docker pull ghcr.io/abossard/lite-gateway:latest
docker run -v ./config.json:/app/config.json:ro -p 8080:8080 ghcr.io/abossard/lite-gateway:latest
```

Multi-arch image (linux/amd64 + linux/arm64). Version tags follow semver: `:1`, `:1.2`, `:1.2.3`, `:latest`.

### Option D: Download a prebuilt binary

| Platform | Download |
| --- | --- |
| Linux x64 | [`LiteGateway.YarpProxy-linux-x64.tar.gz`](../../releases/latest) |
| Linux ARM64 | [`LiteGateway.YarpProxy-linux-arm64.tar.gz`](../../releases/latest) |
| Windows x64 | [`LiteGateway.YarpProxy-win-x64.zip`](../../releases/latest) |
| Windows ARM64 | [`LiteGateway.YarpProxy-win-arm64.zip`](../../releases/latest) |
| macOS Intel | [`LiteGateway.YarpProxy-osx-x64.tar.gz`](../../releases/latest) |
| macOS Apple Silicon | [`LiteGateway.YarpProxy-osx-arm64.tar.gz`](../../releases/latest) |

---

## How Header Forwarding Works

The core concept: YARP's **request transforms** inject (or modify) headers on every
proxied request. This is configured declaratively — no custom middleware needed.

### Config file (`config.json`)

```json
{
  "ReverseProxy": {
    "Routes": {
      "catch-all": {
        "ClusterId": "upstream",
        "Match": { "Path": "{**catch-all}" },
        "Transforms": [
          { "RequestHeader": "X-Custom-Header", "Set": "my-value" }
        ]
      }
    },
    "Clusters": {
      "upstream": {
        "Destinations": {
          "default": { "Address": "http://localhost:3000" }
        }
      }
    }
  }
}
```

Every request through the proxy gets `X-Custom-Header: my-value` added before it
reaches the backend.

### Multiple headers

```json
"Transforms": [
  { "RequestHeader": "X-Tenant-ID", "Set": "customer-42" },
  { "RequestHeader": "X-Gateway", "Set": "lite-gateway" },
  { "RequestHeader": "X-Correlation-ID", "Append": "auto-generated" }
]
```

### Via environment variables

Set headers without a config file using the `PROXY_HEADER_*` shorthand. Underscores
in the name become hyphens. An optional **action prefix** controls behavior:

| Prefix | Action | Direction | Example |
| --- | --- | --- | --- |
| *(none)* | Set | Request | `PROXY_HEADER_X_TENANT_ID=val` |
| `SET_` | Set | Request | `PROXY_HEADER_SET_X_TENANT_ID=val` |
| `APPEND_` | Append | Request | `PROXY_HEADER_APPEND_X_TAG=from-proxy` |
| `REMOVE_` | Remove | Request | `PROXY_HEADER_REMOVE_X_SECRET=` |
| `RESPONSE_SET_` | Set | Response | `PROXY_HEADER_RESPONSE_SET_X_VIA=lite-gw` |
| `RESPONSE_APPEND_` | Append | Response | `PROXY_HEADER_RESPONSE_APPEND_X_TRACE=hop` |

### `_V` suffix — value from another env var

Add `_V` to the end of any `PROXY_HEADER_*` env var to read the header value from
**another environment variable**. This is useful for injecting secrets or values managed
by your orchestrator (Kubernetes, Docker Compose, Azure, etc.):

```bash
# The value of X-Api-Key is read from $MY_API_SECRET at startup
export MY_API_SECRET="sk-abc123"
export PROXY_HEADER_X_API_KEY_V=MY_API_SECRET    # → Set X-Api-Key: "sk-abc123"

# Works with all action prefixes
export PROXY_HEADER_SET_X_AUTH_V=AUTH_TOKEN        # → Set X-Auth: value of $AUTH_TOKEN
export PROXY_HEADER_RESPONSE_SET_X_VER_V=APP_VER  # → Set response X-Ver: value of $APP_VER
```

If the referenced env var is not set, the proxy **crashes with a clear error** at startup.

### Examples

```bash
# Set request headers (backward compatible — no prefix needed)
export PROXY_HEADER_X_TENANT_ID="customer-42"       # → Set X-Tenant-ID: customer-42
export PROXY_HEADER_SET_X_GATEWAY="lite-gw"          # → Set X-Gateway: lite-gw

# Append to existing request header
export PROXY_HEADER_APPEND_X_REQUEST_TAG="from-proxy" # → Append X-Request-Tag: from-proxy

# Remove a request header (strip before forwarding)
export PROXY_HEADER_REMOVE_X_INTERNAL_SECRET=         # → Remove X-Internal-Secret

# Set/append response headers
export PROXY_HEADER_RESPONSE_SET_X_POWERED_BY="lite-gateway"
export PROXY_HEADER_RESPONSE_APPEND_X_TRACE="proxy-hop"

# Resolve from another env var
export PROXY_HEADER_X_API_KEY_V=AZURE_API_KEY         # → Set X-Api-Key: value of $AZURE_API_KEY
```

Or use native YARP env vars for full control:

```bash
export ReverseProxy__Routes__catch-all__Transforms__0__RequestHeader="X-Custom-Header"
export ReverseProxy__Routes__catch-all__Transforms__0__Set="my-value"
export ReverseProxy__Clusters__upstream__Destinations__default__Address="http://backend:3000"
```

---

## Configuration

The proxy loads config from these sources (highest priority wins):

| Priority | Source | Hot-Reload |
| :---: | --- | :---: |
| 3 (highest) | Environment variables | ❌ |
| 2 | Config JSON file (`--config` or `./config.json`) | ✅ |
| 1 | Built-in `appsettings.json` defaults | — |

### Full config example

<details>
<summary>Click to expand</summary>

```json
{
  "ReverseProxy": {
    "Routes": {
      "api": {
        "ClusterId": "api-backend",
        "Match": { "Path": "/api/{**remainder}" },
        "Transforms": [
          { "RequestHeader": "X-Gateway", "Set": "lite-gateway" },
          { "RequestHeader": "X-Tenant-ID", "Set": "acme-corp" }
        ]
      },
      "static": {
        "ClusterId": "static-backend",
        "Match": { "Path": "/static/{**remainder}" }
      }
    },
    "Clusters": {
      "api-backend": {
        "Destinations": {
          "primary": { "Address": "https://api.internal:443" },
          "fallback": { "Address": "https://api-dr.internal:443" }
        },
        "LoadBalancingPolicy": "RoundRobin",
        "HealthCheck": {
          "Active": {
            "Enabled": true,
            "Interval": "00:00:30",
            "Timeout": "00:00:10",
            "Path": "/health"
          }
        }
      },
      "static-backend": {
        "Destinations": {
          "default": { "Address": "http://cdn:8080" }
        }
      }
    }
  }
}
```

</details>

---

## Performance Tuning

All performance parameters are configurable via `GATEWAY_*` environment variables. Defaults
are tuned for high-throughput proxy workloads. The startup banner shows every parameter with
its current value and whether it's `(default)` or `(custom)`.

### Kestrel (inbound connections)

| Variable | Default | Description |
| --- | --- | --- |
| `GATEWAY_MAX_CONNECTIONS` | `20000` | Max concurrent inbound connections |
| `GATEWAY_MAX_UPGRADED_CONNECTIONS` | `20000` | Max concurrent WebSocket/upgraded connections |
| `GATEWAY_KEEPALIVE_TIMEOUT_SEC` | `120` | Keep-alive timeout (seconds) |
| `GATEWAY_REQUEST_HEADER_TIMEOUT_SEC` | `30` | Max time to receive request headers (seconds) |
| `GATEWAY_H2_MAX_STREAMS` | `1024` | HTTP/2 max concurrent streams per connection |
| `GATEWAY_H2_INIT_CONNECTION_WINDOW_KB` | `1024` | HTTP/2 initial connection flow-control window (KB) |
| `GATEWAY_H2_INIT_STREAM_WINDOW_KB` | `768` | HTTP/2 initial per-stream flow-control window (KB) |

### HttpClient (outbound connections)

| Variable | Default | Description |
| --- | --- | --- |
| `GATEWAY_POOL_LIFETIME_SEC` | `300` | Rotate pooled connections after N seconds (picks up DNS changes) |
| `GATEWAY_POOL_IDLE_TIMEOUT_SEC` | `120` | Close idle connections after N seconds |
| `GATEWAY_ENABLE_MULTI_HTTP2` | `true` | Open additional HTTP/2 connections when stream limit is hit |

### Middleware

| Variable | Default | Description |
| --- | --- | --- |
| `GATEWAY_COMPRESSION` | `false` | Enable Brotli + Gzip response compression |

### Thread pool

| Variable | Default | Description |
| --- | --- | --- |
| `GATEWAY_MIN_THREADS` | *(not set)* | Pre-allocate min worker/IO threads (avoids ramp-up delay under burst) |

### Docker example

```bash
docker run \
  -v ./config.json:/app/config.json:ro \
  -e GATEWAY_KEEPALIVE_TIMEOUT_SEC=180 \
  -e GATEWAY_POOL_LIFETIME_SEC=600 \
  -e GATEWAY_COMPRESSION=true \
  -e GATEWAY_MIN_THREADS=200 \
  -p 8080:8080 lite-gateway
```

### Docker Compose with kernel tuning

```yaml
services:
  gateway:
    build:
      context: .
      dockerfile: src/LiteGateway.YarpProxy/Dockerfile
    environment:
      GATEWAY_COMPRESSION: "true"
      GATEWAY_MIN_THREADS: "200"
    ports:
      - "8080:8080"
    sysctls:
      net.core.somaxconn: "65535"
      net.ipv4.ip_local_port_range: "1024 65535"
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
```

---

## OpenTelemetry

The proxy has built-in OpenTelemetry support for **traces**, **metrics**, and **logs**.
It is entirely opt-in — set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable export to any
OTLP-compatible collector (Jaeger, Grafana Tempo, Azure Monitor, etc.).

### Signals exported

| Signal | What's captured |
| --- | --- |
| **Traces** | Inbound HTTP requests (ASP.NET Core), outbound forwarded requests (HttpClient), YARP proxy pipeline (`Yarp.ReverseProxy`) |
| **Metrics** | Request duration, active connections, request/response sizes, HTTP client connection pool stats |
| **Logs** | All application logs (with scopes and formatted messages) |

### Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(unset — OTel disabled)* | OTLP collector endpoint (e.g., `http://collector:4317`) |
| `OTEL_SERVICE_NAME` | `lite-gateway` | Service name in traces/metrics |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` | Protocol: `grpc` or `http/protobuf` |

All standard `OTEL_*` env vars are supported — see the
[OpenTelemetry spec](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).

### Docker example

```bash
docker run \
  -v ./config.json:/app/config.json:ro \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317 \
  -e OTEL_SERVICE_NAME=my-gateway \
  -p 8080:8080 lite-gateway
```

### Docker Compose with a collector

```yaml
services:
  gateway:
    build:
      context: .
      dockerfile: src/LiteGateway.YarpProxy/Dockerfile
    volumes:
      - ./config/yarp.json:/app/config.json:ro
    ports:
      - "8080:8080"
    environment:
      OTEL_EXPORTER_OTLP_ENDPOINT: http://otel-collector:4317
      OTEL_SERVICE_NAME: lite-gateway

  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    ports:
      - "4317:4317"   # OTLP gRPC
      - "4318:4318"   # OTLP HTTP
    volumes:
      - ./otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro
```

---

## Docker

```bash
# Build
docker build -t lite-gateway -f src/LiteGateway.YarpProxy/Dockerfile .

# Run with config file
docker run -v ./config.json:/app/config.json:ro -p 8080:8080 lite-gateway

# Run with env vars only
docker run \
  -e PROXY_HEADER_X_TENANT_ID=customer-42 \
  -e ReverseProxy__Clusters__upstream__Destinations__default__Address=http://host.docker.internal:3000 \
  -p 8080:8080 lite-gateway
```

| Property | Value |
| --- | --- |
| Base image | `runtime-deps:10.0-noble-chiseled` (distroless) |
| Shell | None |
| User | Non-root |
| Size | ~15–25 MB |

### Official Microsoft YARP Docker Image

Microsoft publishes a pre-built YARP container image. It is currently in **Preview**
and only available in the nightly repository:

```bash
docker pull mcr.microsoft.com/dotnet/nightly/yarp:latest
```

The official image is a generic, config-driven reverse proxy — mount a JSON config file
to `/etc/yarp.config` and it handles routing on port 5000:

```bash
docker run --rm \
  -v $(pwd)/config.json:/etc/yarp.config \
  -p 5000:5000 \
  mcr.microsoft.com/dotnet/nightly/yarp:latest
```

It also supports OpenTelemetry via the `OTEL_EXPORTER_OTLP_ENDPOINT` environment
variable.

> **Why this project uses a custom image instead:** Lite Gateway compiles to a Native
> AOT binary, which is smaller (~15 MB vs ~80 MB), starts faster, and supports the
> `PROXY_HEADER_*` environment variable shorthand for header injection. The official
> image doesn't support custom middleware or the env-var header convention.

For more details see the
[Docker Hub page](https://hub.docker.com/r/microsoft/dotnet-nightly-yarp) and the
tracking issue for the stable release:
[dotnet/dotnet-docker#6436](https://github.com/dotnet/dotnet-docker/issues/6436).

## Build from Source

**Prerequisites:** [.NET 10 SDK](https://dot.net). For AOT: C/C++ toolchain.

```bash
# Development (JIT)
dotnet run --project src/LiteGateway.YarpProxy

# AOT publish (single-file binary)
dotnet publish src/LiteGateway.YarpProxy -c Release -r linux-x64
```

## Windows

See [docs/yarp-proxy-windows.md](docs/yarp-proxy-windows.md) for the full Windows guide:
PowerShell examples, Windows Service setup, IIS integration, and troubleshooting.

## CI/CD

The GitHub Actions workflow [`.github/workflows/release-yarp.yml`](.github/workflows/release-yarp.yml)
builds Native AOT binaries for 6 platforms and publishes them as GitHub Release assets
on every version tag (`v*`).

## Project Structure

```
src/LiteGateway.YarpProxy/   ← the proxy (Program.cs + YARP config)
config/                       ← example YARP config for Docker
docs/                         ← deployment guides (Windows, etc.)
scripts/                      ← build scripts (Windows AOT)
archive/                      ← legacy benchmark code (see archive/README.md)
```

## Reference

- [YARP Documentation](https://microsoft.github.io/reverse-proxy/)
- [YARP Config File Reference](https://microsoft.github.io/reverse-proxy/articles/config-files.html)
- [YARP Request Transforms](https://microsoft.github.io/reverse-proxy/articles/transforms.html)
- [Official YARP Docker Image (Preview)](https://hub.docker.com/r/microsoft/dotnet-nightly-yarp)
- [Native AOT Deployment](https://learn.microsoft.com/dotnet/core/deploying/native-aot/)
