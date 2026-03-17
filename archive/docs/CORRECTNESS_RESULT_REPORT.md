# Correctness Verification Result Report

## Scope completed

1. **Load client correctness defaults**
   - Single and matrix runs now use one execution path (`RunAsync`), with matrix behavior configured via `ConfigureMatrixRun`.
   - Default request semantics are now:
     - `POST` JSON body (large template aligned with the reference plan shape).
     - `correlationId` query parameter.
     - response assertions: status code `200` and `$.correlationId` equality with sent correlation id.
2. **.NET proxy standalone behavior**
   - Standalone mode now reads the incoming request body, awaits async sleep, and echoes the body back with status `200`.
3. **Rust proxy standalone behavior**
   - Standalone mode now reads the incoming request body, awaits async sleep, and echoes the body back with status `200`.
4. **JMeter automation**
   - Added `scripts/run-jmeter-testplan.sh` to run `.temp/Test Plan.jmx` in non-GUI mode against .NET and/or Rust with client cert + truststore setup.

## Validation runs

### Build checks

```bash
dotnet build src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj -c Release
dotnet build src/LiteGateway.Proxy/LiteGateway.Proxy.csproj -c Release
cargo check --manifest-path src/LiteGateway.Proxy.Rust/Cargo.toml
```

Result: **pass**

### Host load-client matrix assertions

```bash
./scripts/run-everything.sh --quick --skip-build
```

Result: **pass** for both .NET and Rust, with `assertion_failed=0` across all matrix scenarios.

### Docker matrix assertions

```bash
./scripts/run-docker-matrix.sh --quick
```

Result: **pass** for both .NET and Rust, with all matrix scenarios reporting `status=ok`, `error_pct=0.00`, and no failed/assertion-failed request lines in logs.

### JMeter non-GUI verification

```bash
./scripts/run-jmeter-testplan.sh --proxy both --skip-build
```

Observed output:

- .NET: `total=7500 failed=0 assertion_failed=0`
- Rust: `total=7500 failed=0 assertion_failed=0`

Result: **pass** for both .NET and Rust.

## Artifacts

- Host matrix logs: `.run-logs/`
- Docker matrix logs: `.run-logs/docker/`
- JMeter logs/results: `.run-logs/jmeter/`
  - `.run-logs/jmeter/dotnet/summary.txt`
  - `.run-logs/jmeter/rust/summary.txt`
