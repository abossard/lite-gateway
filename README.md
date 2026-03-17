# Lite Gateway

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

### Option C: Download a prebuilt binary

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

Set headers without a config file using the `PROXY_HEADER_*` shorthand — underscores
become hyphens in the header name:

```bash
export PROXY_HEADER_X_TENANT_ID="customer-42"   # → X-Tenant-ID: customer-42
export PROXY_HEADER_X_CUSTOM="hello"             # → X-Custom: hello
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
- [Native AOT Deployment](https://learn.microsoft.com/dotnet/core/deploying/native-aot/)
