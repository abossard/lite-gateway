# Archive

This directory contains the legacy benchmark scaffold that was the original purpose
of this repository — comparing .NET, Rust, and YARP reverse proxy implementations.

The project has since been refocused on **YARP** as the sole implementation.
See the [root README](../README.md) for the current project.

## What's here

| Directory | Description |
| --- | --- |
| `src/LiteGateway.Proxy/` | .NET custom proxy (echo/forward mode) |
| `src/LiteGateway.Proxy.Rust/` | Rust proxy (hyper-based) |
| `src/LiteGateway.LoadClient/` | .NET load-testing client |
| `docker-compose.yml` | Docker Compose for the .NET + Rust proxy matrix |
| `scripts/` | Benchmark automation scripts |
| `specs/` | Original specification and JMeter test plans |
| `docs/` | Benchmark results, architecture diagrams, correctness reports |
| `certs/` | mTLS certificate generation artifacts |
| `artifacts/` | Build output directory |
