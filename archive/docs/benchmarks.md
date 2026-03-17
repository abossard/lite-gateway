# Benchmark Results (Historical)

This repository originally served as a benchmark scaffold comparing .NET, Rust, and YARP proxies.
The YARP Proxy has since become the primary product. These benchmark results are preserved for reference.

## Components (Legacy)

| Component | Path | Description |
| --- | --- | --- |
| .NET Proxy | `src/LiteGateway.Proxy` | Kestrel-based, allocation-conscious reverse proxy |
| Rust Proxy | `src/LiteGateway.Proxy.Rust` | Hyper + Rustls equivalent |
| Load Client | `src/LiteGateway.LoadClient` | Async load generator with TUI dashboard |

## Proxy Comparison (Release AOT, local machine)

| Scenario | .NET (RPS) | Rust (RPS) |
| --- | ---: | ---: |
| http-reuse | 1025.98 | 1048.16 |
| http-no-reuse | 732.59 | 510.12 |
| https-reuse | 1092.05 | 1091.01 |
| https-no-reuse | 245.50 | 617.07 |
| https-mtls-reuse | 1091.88 | 1090.88 |
| https-mtls-no-reuse | 116.02 | 200.19 |

## YARP Proxy Throughput

| Tool | Concurrency | Duration | RPS | Avg Latency | Errors |
| --- | ---: | --- | ---: | ---: | ---: |
| **hey** | 200 | 10s | **18,310** | 10.9ms | 0% |
| **wrk** | 200 (8 threads) | 10s | **20,983** | 9.9ms | 0% |
| **JMeter** | 500 × 10 loops | 5s | **989** | 3ms | 0% |
| **JMeter** (high-scale) | 5000 × 10 loops | 36s | **1,382** | 714ms | 5.2%¹ |

¹ High-scale errors are connection timeouts from Docker Desktop networking limits, not YARP.

## Run Scripts

```bash
# Host-based matrix
./scripts/run-everything.sh --quick --proxy both

# Docker-based matrix
./scripts/run-docker-matrix.sh --quick --proxy both

# JMeter
./scripts/run-jmeter-testplan.sh --proxy both
```

See `specs/ABSTRACT_SPEC.md` for the original specification.
