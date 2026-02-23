# Lite Gateway Benchmark Scaffold

High-performance .NET 10 Native AOT scaffold for an mTLS reverse proxy and a matching high-concurrency CLI load client.

## Concept
- **Proxy (`src/LiteGateway.Proxy`)**: allocation-conscious Kestrel service with three simultaneous endpoints: HTTP (`8080`), HTTPS (`8443`, no client cert), and HTTPS+mTLS (`9443`), plus async per-request delay path (default `5s`) and optional upstream forwarding; standalone mode echoes request JSON after the delay.
- **Rust Proxy (`src/LiteGateway.Proxy.Rust`)**: equivalent async proxy behavior using Hyper + Rustls with the same endpoint model (HTTP/HTTPS/mTLS), async delay path, optional upstream forwarding, and standalone request-body echo.
- **Load Client (`src/LiteGateway.LoadClient`)**: async load generator with a real terminal TUI dashboard (live RPS/p95 graphs, throughput, latency, inflight, errors, opened TCP connections), matrix mode, and autotune. Default request/validation behavior is `POST` JSON + correlation query and response assertions (status `200`, `$.correlationId` match).
- **Certificates (`scripts/generate-mtls-certs.sh`)**: local ECDSA P-256 CA/server/client cert generation for reproducible mTLS runs.

## Architecture
![Lite Gateway architecture](docs/architecture.svg)

Draw.io source: `docs/architecture.drawio`

## Project Setup

### Prerequisites
- .NET 10 SDK
- Rust (stable toolchain with Cargo)
- OpenSSL

### 1) Generate mTLS artifacts
```bash
./scripts/generate-mtls-certs.sh certs/generated
source certs/generated/mtls.env
```

### 2) Run proxy
```bash
dotnet run --project src/LiteGateway.Proxy/LiteGateway.Proxy.csproj --no-build
```

### 2b) Run Rust proxy (alternative implementation)
```bash
# Uses the same LITEGATEWAY_Proxy__* environment variables from certs/generated/mtls.env.
# If ServerCertificatePath points to server.pfx, the Rust proxy auto-resolves
# server.cert.pem/server.key.pem from the same directory.
cargo run --manifest-path src/LiteGateway.Proxy.Rust/Cargo.toml --release
```

### 3) Run load client
```bash
dotnet run --project src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj --no-build -- \
  --url https://localhost:9443/api/test \
  --cert-pfx "$CLIENT_PFX" \
  --cert-password "$CLIENT_PFX_PASSWORD" \
  --custom-ca "$CLIENT_CA_CERT" \
  --concurrency 1024 \
  --duration 60 \
  --http-version 2 \
  --max-request-time 20 \
  --ramp-percent-per-second 10
```

### 4) Run automatic matrix + autotune (all 6 combinations)
```bash
dotnet run --project src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj --no-build -- --mode matrix
```

Matrix mode tests, in sequence:
- HTTP reuse / HTTP no-reuse
- HTTPS reuse / HTTPS no-reuse
- HTTPS+mTLS reuse / HTTPS+mTLS no-reuse

### 5) One-command automation (certs + build + matrix)
```bash
# Quick profile (recommended for day-to-day checks)
./scripts/run-everything.sh --quick --proxy both

# Full profile (uses load client matrix defaults; much longer)
./scripts/run-everything.sh --full --proxy both
```

What it does:
- Regenerates ECDSA certs (`certs/generated`) unless `--skip-certs` is passed.
- Builds .NET proxy + load client (and Rust proxy when requested) unless `--skip-build` is passed.
- Runs matrix mode against the .NET and/or Rust proxy on ports `8080`, `8443`, `9443`.
- Stores logs under `.run-logs/` (`dotnet-proxy.log`, `dotnet-matrix.log`, `rust-proxy.log`, `rust-matrix.log`).

### 6) Docker end-to-end automation (both proxies + host client)
```bash
# Quick profile (tested)
./scripts/run-docker-matrix.sh --quick --proxy both

# Full profile (longer)
./scripts/run-docker-matrix.sh --full --proxy both
```

Docker host port mappings:
- .NET proxy: `18080` / `18443` / `19443` -> container `8080` / `8443` / `9443`
- Rust proxy: `28080` / `28443` / `29443` -> container `8080` / `8443` / `9443`

What the Docker script does:
- Regenerates certs and builds host load client.
- Builds Docker images from `src/LiteGateway.Proxy/Dockerfile` and `src/LiteGateway.Proxy.Rust/Dockerfile`.
- Starts requested services from `docker-compose.yml`.
- Runs matrix client against each containerized proxy using mapped URLs.
- Writes logs to `.run-logs/docker/`.

### 7) Run the reference JMeter plan (non-GUI)
```bash
# Run the git-managed test plan copy against both services
./scripts/run-jmeter-testplan.sh --proxy both

# Run with the built-in high-scale preset
./scripts/run-jmeter-testplan.sh --proxy both --high-scale

# Or explicitly point to the tracked file
./scripts/run-jmeter-testplan.sh --plan specs/jmeter/TestPlan.jmx --proxy both

# Run only one service
./scripts/run-jmeter-testplan.sh --proxy dotnet
./scripts/run-jmeter-testplan.sh --proxy rust

# Fully custom scale knobs
./scripts/run-jmeter-testplan.sh --proxy both \
  --threads 20000 \
  --ramp-seconds 45 \
  --loops 12 \
  --connect-timeout-ms 120000 \
  --response-timeout-ms 120000
```

What it does:
- Regenerates certs unless `--skip-certs` is passed.
- Starts selected proxy implementation(s) on the mTLS endpoint.
- Runs `specs/jmeter/TestPlan.jmx` (git-managed copy of the reference plan) in non-GUI mode with client cert + truststore config.
- Applies runtime scale overrides (threads/ramp/loops/timeouts) when passed to the script.
- Validates the generated JTL to require zero failed samples/assertions.
- Writes logs/results to `.run-logs/jmeter/`.

Latest tested Docker quick-run summary (`--quick --proxy both`, local machine):

| Scenario | .NET in Docker | Rust in Docker |
| --- | ---: | ---: |
| http-reuse | 19.43 | 20.90 |
| http-no-reuse | 19.42 | 19.42 |
| https-reuse | 25.91 | 24.91 |
| https-no-reuse | 19.87 | 19.41 |
| https-mtls-reuse | 20.56 | 20.03 |
| https-mtls-no-reuse | 19.40 | 19.41 |

### Recommended for performance runs: Release Native AOT binaries
`dotnet run` is fine for local dev, but benchmark runs should use published Release AOT binaries.

```bash
# Apple Silicon Mac (switch runtime for your platform, e.g. osx-x64 / linux-x64)
dotnet publish src/LiteGateway.Proxy/LiteGateway.Proxy.csproj -c Release -r osx-arm64 --self-contained true /p:PublishAot=true
dotnet publish src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj -c Release -r osx-arm64 --self-contained true /p:PublishAot=true

./src/LiteGateway.Proxy/bin/Release/net10.0/osx-arm64/publish/LiteGateway.Proxy
./src/LiteGateway.LoadClient/bin/Release/net10.0/osx-arm64/publish/LiteGateway.LoadClient --mode matrix
```

### Test duration defaults
- Single mode runtime is controlled by `--duration` (default: `60s`).
- Matrix mode runtime per autotune attempt is `--matrix-run-duration` (default: `20s`).
- Full matrix total time depends on autotune steps and usually lands around 12-22 minutes with defaults.

### Optional "no keep-alive style" single run
```bash
dotnet run --project src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj --no-build -- \
  --url https://localhost:9443/ \
  --cert-pfx "$CLIENT_PFX" \
  --cert-password "$CLIENT_PFX_PASSWORD" \
  --custom-ca "$CLIENT_CA_CERT" \
  --concurrency 256 \
  --duration 20 \
  --http-version 1.1 \
  --connection-close
```

## Recent Local .NET vs Rust Snapshot
Assuming the first pasted matrix run targeted the .NET proxy and the second targeted the Rust proxy on the same machine/config:

| Scenario | .NET success RPS | Rust success RPS |
| --- | ---: | ---: |
| http-reuse | 1025.98 | 1048.16 |
| http-no-reuse | 732.59 | 510.12 |
| https-reuse | 1092.05 | 1091.01 |
| https-no-reuse | 245.50 | 617.07 |
| https-mtls-reuse | 1091.88 | 1090.88 |
| https-mtls-no-reuse | 116.02 | 200.19 |

Quick read:
- Reuse-mode throughput is effectively tied (~1.09k RPS) across HTTPS and mTLS.
- No-reuse TLS/mTLS favored Rust in this sample (higher handshake-heavy throughput).
- No-reuse plain HTTP favored .NET in this sample; run-to-run variance is still significant.

## Performance Note
- Highest observed local peak during prior sweep: **~1526.3 RPS** (HTTP/2, mTLS, high concurrency, local machine dependent).

## Abstract Spec
See `specs/ABSTRACT_SPEC.md`.

Source requirement documents:
- `specs/Lite Gateway Requirement.txt`
- `specs/Cloud Lite  Gateway_ Performance.txt`
