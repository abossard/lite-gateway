# YARP Reverse Proxy — Header Injection Gateway

A vanilla [YARP](https://microsoft.github.io/reverse-proxy/) reverse proxy with Native AOT,
chiseled Docker image, and flexible header injection from external configuration.

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │  Docker Container (chiseled, ~15 MB)    │
  ┌──────────┐          │                                         │          ┌──────────┐
  │  Client   │──HTTP──▶│  YARP Reverse Proxy (AOT binary)        │──HTTP──▶│ Backend  │
  │ (JMeter)  │         │                                         │         │ (echo)   │
  └──────────┘          │  Config sources (priority order):       │          └──────────┘
                        │   1. appsettings.json (baked)           │
                        │   2. /config/yarp.json (mounted)        │
                        │   3. Environment variables               │
                        │   4. PROXY_HEADER_* (auto-translated)   │
                        └─────────────────────────────────────────┘
```

## Quick Start

```bash
# Build and run with docker compose
docker compose -f docker-compose.yarp.yml up --build

# Test header injection
curl -s http://localhost:38080/api/test -d '{"hello":"world"}' -H 'Content-Type: application/json'
```

## Header Injection — Three Approaches

All approaches use **100% vanilla YARP** configuration. No custom proxy code.
The Docker image stays **immutable** across all approaches.

### Approach 1: Mounted Config File (recommended)

Mount a JSON file at `/config/yarp.json` with YARP route transforms:

```json
{
  "ReverseProxy": {
    "Routes": {
      "catch-all": {
        "Transforms": [
          { "RequestHeader": "TEST-ID", "Set": "1234" }
        ]
      }
    },
    "Clusters": {
      "upstream": {
        "Destinations": {
          "default": { "Address": "http://backend:8080" }
        }
      }
    }
  }
}
```

```bash
docker run -v ./config/yarp.json:/config/yarp.json:ro -p 8080:8080 yarp-proxy
```

**Hot-reload**: YARP watches this file. Edit it and YARP picks up changes without restart.

**Kubernetes**: Use a ConfigMap mounted at `/config/yarp.json`.

### Approach 2: YARP Native Environment Variables

YARP reads configuration from .NET's `IConfiguration`, which includes env vars.
Use `__` as the path separator:

```bash
docker run \
  -e ReverseProxy__Routes__catch-all__Transforms__0__RequestHeader=TEST-ID \
  -e ReverseProxy__Routes__catch-all__Transforms__0__Set=1234 \
  -e ReverseProxy__Clusters__upstream__Destinations__default__Address=http://backend:8080 \
  -p 8080:8080 yarp-proxy
```

Or in docker-compose:

```yaml
environment:
  ReverseProxy__Routes__catch-all__Transforms__0__RequestHeader: "TEST-ID"
  ReverseProxy__Routes__catch-all__Transforms__0__Set: "1234"
  ReverseProxy__Clusters__upstream__Destinations__default__Address: "http://backend:8080"
```

### Approach 3: `PROXY_HEADER_*` Environment Variables

For simple use cases, set `PROXY_HEADER_<NAME>=<value>` env vars.
The name part is converted: underscores → hyphens.

```bash
docker run \
  -e PROXY_HEADER_TEST_ID=1234 \
  -e PROXY_HEADER_X_CORRELATION_ID=abc-123 \
  -e ReverseProxy__Clusters__upstream__Destinations__default__Address=http://backend:8080 \
  -p 8080:8080 yarp-proxy
```

This adds two request headers to every proxied request:
- `TEST-ID: 1234`
- `X-CORRELATION-ID: abc-123`

## Dynamic ENV Var Name Scenario

**Problem**: An external system provides `TEST_123_ID=1234` today. Tomorrow it
might provide `TEST_456_ID=5678` instead. The header name should stay `TEST-ID`.

**Solution**: Map the externally-named var to the standardized `PROXY_HEADER_TEST_ID`
in the deployment manifest (not in the Docker image):

```yaml
# docker-compose.yml
services:
  yarp-proxy:
    image: yarp-proxy:latest
    environment:
      # Today: external system sets TEST_123_ID=1234
      PROXY_HEADER_TEST_ID: "${TEST_123_ID}"
      # Tomorrow: just change to ${TEST_456_ID} — image stays the same
      # PROXY_HEADER_TEST_ID: "${TEST_456_ID}"
```

The Docker image **never changes**. Only the compose/manifest file is updated.

## Docker Image Details

| Property | Value |
| --- | --- |
| Base | `runtime-deps:10.0-noble-chiseled` |
| Compilation | Native AOT (ahead-of-time, no JIT) |
| Shell | None (distroless) |
| Package manager | None |
| User | Non-root (`$APP_UID`) |
| Estimated size | ~15–25 MB |

Multi-stage Dockerfile:
1. **Build stage**: `dotnet/sdk:10.0` — restores, publishes with AOT
2. **Runtime stage**: `runtime-deps:10.0-noble-chiseled` — copies only the native binary

## Building

```bash
# AOT Docker build
docker build -t yarp-proxy -f src/LiteGateway.YarpProxy/Dockerfile .

# Local development (non-AOT)
dotnet run --project src/LiteGateway.YarpProxy/LiteGateway.YarpProxy.csproj

# Local AOT publish
dotnet publish src/LiteGateway.YarpProxy/LiteGateway.YarpProxy.csproj \
  -c Release -r osx-arm64 --self-contained true /p:PublishAot=true
```

## JMeter Integration

The existing JMeter test plan (`specs/jmeter/TestPlan.jmx`) works with the YARP
proxy. Point JMeter at the YARP proxy port instead of the backend directly:

```bash
# YARP proxy sits in front, injects headers, forwards to backend
# JMeter → :38080 (YARP) → :8080 (backend echo)
```

The injected headers (e.g., `TEST-ID`) are added transparently by YARP transforms
before forwarding to the upstream. The backend echoes the full request including
the injected headers.

## Load Test Results

All tests run with YARP proxy (AOT, Docker chiseled) → backend (echo, 0ms delay).

### Header Injection Proof

```
$ PROXY_HEADER_TEST_ID=1234 PROXY_HEADER_X_CORRELATION_ID=abc-def-999

→ Backend receives:
  "TEST-ID": "1234",
  "X-CORRELATION-ID": "abc-def-999"
```

### Throughput Benchmarks

| Tool | Concurrency | Duration | RPS | Avg Latency | Errors |
| --- | ---: | --- | ---: | ---: | ---: |
| **hey** | 200 | 10s | **18,310** | 10.9ms | 0% |
| **wrk** | 200 (8 threads) | 10s | **20,983** | 9.9ms | 0% |
| **JMeter** | 500 × 10 loops | 5s | **989** | 3ms | 0% |
| **JMeter** (high-scale) | 5000 × 10 loops | 36s | **1,382** | 714ms | 5.2%¹ |

¹ High-scale errors are connection timeouts from Docker Desktop networking limits, not YARP.

### JMeter Validation

The existing JMeter test plan (`specs/jmeter/TestPlan.jmx`) validates:
- HTTP 200 response code
- JSON body integrity (correlationId roundtrip)
- Both assertions pass through the YARP proxy at 100% success (500-thread test).

## Files

```
src/LiteGateway.YarpProxy/
├── Dockerfile                  # Multi-stage AOT + chiseled
├── LiteGateway.YarpProxy.csproj # .NET 10, AOT, YARP 2.3.0
├── Program.cs                  # Minimal: config loading + YARP setup
├── appsettings.json            # Default YARP routes/clusters
├── appsettings.Development.json
├── entrypoint.sh               # Alternative: shell-based env var translation
└── Properties/
    └── launchSettings.json

config/
├── yarp.json                   # Example mounted config with header transforms
└── README.md                   # Config examples for all approaches

docker-compose.yarp.yml         # Compose with backend + YARP proxy
```
