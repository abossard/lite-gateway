# Lite Gateway — YARP Reverse Proxy

A lightweight, high-performance reverse proxy built on [YARP](https://microsoft.github.io/reverse-proxy/)
with **.NET 10 Native AOT**. It forwards HTTP requests to a backend and injects custom headers —
all through declarative configuration, zero custom proxy code.

```
  Client ──▶ Lite Gateway (8080) ──▶ Backend API
              ├─ injects headers
              ├─ routes by path
              └─ hot-reloads config
```

## Download

Prebuilt binaries for all platforms — single file, zero dependencies:

| Platform | Download |
| --- | --- |
| **Linux x64** | [`LiteGateway.YarpProxy-linux-x64.tar.gz`](../../releases/latest) |
| **Linux ARM64** | [`LiteGateway.YarpProxy-linux-arm64.tar.gz`](../../releases/latest) |
| **Windows x64** | [`LiteGateway.YarpProxy-win-x64.zip`](../../releases/latest) |
| **Windows ARM64** | [`LiteGateway.YarpProxy-win-arm64.zip`](../../releases/latest) |
| **macOS Intel** | [`LiteGateway.YarpProxy-osx-x64.tar.gz`](../../releases/latest) |
| **macOS Apple Silicon** | [`LiteGateway.YarpProxy-osx-arm64.tar.gz`](../../releases/latest) |

Or build from source: `dotnet publish src/LiteGateway.YarpProxy -c Release -r <rid>`

## Quick Start

### 1. Create a config file

Create `config.json` in the directory where you'll run the proxy:

```json
{
  "ReverseProxy": {
    "Routes": {
      "catch-all": {
        "ClusterId": "upstream",
        "Match": { "Path": "{**catch-all}" },
        "Transforms": [
          { "RequestHeader": "X-Tenant-ID", "Set": "customer-42" }
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

### 2. Run

```bash
# Linux / macOS
./LiteGateway.YarpProxy

# Windows (PowerShell)
.\LiteGateway.YarpProxy.exe

# Or specify a config path
./LiteGateway.YarpProxy --config /path/to/my-config.json
```

### 3. Test

```bash
curl http://localhost:8080/api/test
# → Forwarded to http://localhost:3000/api/test with header X-Tenant-ID: customer-42
```

### What you'll see at startup

```
╔══════════════════════════════════════════════════════════════╗
║           Lite Gateway — YARP Reverse Proxy                 ║
╚══════════════════════════════════════════════════════════════╝

  ✅ Config file : /app/config.json
  ✅ PROXY_HEADER_* env vars (2 detected):
       PROXY_HEADER_TEST_ID → TEST-ID: 1234
       PROXY_HEADER_X_TENANT_ID → X-TENANT-ID: customer-42
  🌐 Listen URL  : http://+:8080
```

If something is wrong, the proxy tells you:

```
  ⚠️  Config file : /app/config.json (NOT FOUND)
  ⚠️  WARNING: Cluster 'upstream' → http://localhost:5000 (default — did you forget to set the upstream?)
```

---

## Configuration

The proxy loads configuration from these sources (highest priority wins):

| Priority | Source | Hot-Reload |
| :---: | --- | :---: |
| **3 (highest)** | Environment variables | ❌ |
| **2** | Config JSON file (`--config` or `./config.json`) | ✅ |
| **1** | Built-in `appsettings.json` defaults | — |

### Config File (recommended)

By default the proxy looks for `config.json` **in the working directory**.
Override with `--config` (or `-c`):

```bash
./LiteGateway.YarpProxy --config /etc/lite-gateway/production.json
```

The file uses standard [YARP configuration](https://microsoft.github.io/reverse-proxy/articles/config-files.html).
Changes are picked up automatically — **no restart needed**.

<details>
<summary>📋 Full config example (click to expand)</summary>

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

### Environment Variables

Set YARP config via env vars using `__` as the path separator:

```bash
export ReverseProxy__Clusters__upstream__Destinations__default__Address="http://backend:3000"
export ReverseProxy__Routes__catch-all__Transforms__0__RequestHeader="X-Tenant-ID"
export ReverseProxy__Routes__catch-all__Transforms__0__Set="customer-42"
```

### `PROXY_HEADER_*` Shorthand

The simplest way to inject headers — underscores become hyphens:

```bash
export PROXY_HEADER_X_TENANT_ID="customer-42"      # → X-Tenant-ID: customer-42
export PROXY_HEADER_X_CORRELATION_ID="abc-123"      # → X-Correlation-ID: abc-123
export PROXY_HEADER_TEST_ID="1234"                   # → TEST-ID: 1234
```

### Listen Address

```bash
export ASPNETCORE_URLS="http://+:9090"               # default: http://localhost:8080
```

---

## Docker

```bash
# Build
docker build -t lite-gateway -f src/LiteGateway.YarpProxy/Dockerfile .

# Run with config file
docker run -v ./config.json:/app/config.json:ro -p 8080:8080 lite-gateway

# Run with env vars
docker run \
  -e PROXY_HEADER_X_TENANT_ID=customer-42 \
  -e ReverseProxy__Clusters__upstream__Destinations__default__Address=http://host.docker.internal:3000 \
  -p 8080:8080 lite-gateway
```

### Docker Compose

```yaml
services:
  gateway:
    build:
      context: .
      dockerfile: src/LiteGateway.YarpProxy/Dockerfile
    volumes:
      - ./config.json:/app/config.json:ro
    ports:
      - "8080:8080"
```

See [`docker-compose.yarp.yml`](docker-compose.yarp.yml) for a full example with a backend service.

| Property | Value |
| --- | --- |
| Base image | `runtime-deps:10.0-noble-chiseled` (distroless) |
| Shell | None |
| User | Non-root |
| Size | ~15–25 MB |

---

## Build from Source

**Prerequisites:** [.NET 10 SDK](https://dot.net). For AOT: C/C++ toolchain (clang on Linux/macOS, VS Build Tools on Windows).

```bash
# Development (JIT)
dotnet run --project src/LiteGateway.YarpProxy

# AOT publish (single-file binary)
dotnet publish src/LiteGateway.YarpProxy -c Release -r linux-x64     # or osx-arm64, win-x64, etc.
```

## Windows

See [**docs/yarp-proxy-windows.md**](docs/yarp-proxy-windows.md) for the full Windows guide:
PowerShell examples, Windows Service setup, IIS integration, and troubleshooting.

## CI/CD

The GitHub Actions workflow [`.github/workflows/release-yarp.yml`](.github/workflows/release-yarp.yml)
builds Native AOT binaries for 6 platforms (Linux/Windows/macOS × x64/ARM64) and publishes
them as GitHub Release assets on every version tag (`v*`).

## Performance

Benchmarked with YARP proxy (AOT, Docker) forwarding to an echo backend:

| Tool | Concurrency | RPS | Avg Latency |
| --- | ---: | ---: | ---: |
| **hey** | 200 | **18,310** | 10.9 ms |
| **wrk** | 200 | **20,983** | 9.9 ms |

## Reference

- [YARP Documentation](https://microsoft.github.io/reverse-proxy/)
- [YARP Config File Reference](https://microsoft.github.io/reverse-proxy/articles/config-files.html)
- [Native AOT Deployment](https://learn.microsoft.com/dotnet/core/deploying/native-aot/)

---

<details>
<summary>📁 Legacy benchmark scaffold</summary>

This repository originally contained a benchmark scaffold comparing .NET, Rust, and YARP proxies.
The benchmark components (`src/LiteGateway.Proxy`, `src/LiteGateway.Proxy.Rust`,
`src/LiteGateway.LoadClient`) and related scripts remain in the repo for reference.
See `docs/benchmarks.md` for historical benchmark results and `specs/` for the original specification.

</details>
