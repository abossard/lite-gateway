# JMX Parity Plan

## Goal
Make the current .NET and Rust proxy implementations fully satisfy the behavior expected by `.temp/Test Plan.jmx`, then verify with both CLI checks and JMeter non-GUI runs.

## What the JMX test expects
From `.temp/Test Plan.jmx`:

- HTTPS target default: port `443`
- mTLS client auth (inferred from demo/deploy cert setup under `.temp`)
- Request pattern:
  - `POST /api/test?correlationId=5ac318d4-5e88-4b37-8ed1-${UiidC}`
  - JSON body includes `"correlationId": "5ac318d4-5e88-4b37-8ed1-${UiidC}"`
  - Headers include `Content-Type: application/json`
- Assertions:
  - HTTP status code must be `200`
  - Extract `$.correlationId` from response JSON and assert it equals the sent value
- Load shape defaults:
  - 1500 threads
  - 5s ramp-up
  - 5 loops
  - 60s connect timeout
  - 60s response timeout

Important: all numeric values above should be treated as **default parameters**, not hardcoded constants.

## Current gap (verified)
Current standalone behavior in both proxies returns:

```json
{"status":"ok","mode":"standalone"}
```

This passes `200` but fails the JMX correlation assertion because response JSON does not echo `correlationId`.

## Implementation plan

### 1) Add explicit JMX-compatible standalone mode (both proxies)
Introduce a config switch (default keeps current behavior), e.g.:

- `Proxy:StandaloneMode = Static | EchoRequestBody`

Behavior for `EchoRequestBody`:

1. Read request body bytes fully
2. Apply async delay (`Task.Delay` / `tokio::time::sleep`)
3. Return the request body as response (`200`, `Content-Type: application/json`)

Notes:
- Preserve existing upstream forwarding path unchanged.
- Preserve existing static standalone mode as default for backward compatibility.

### 2) Add JMX run wrapper scripts
Add scripts to run either proxy in JMX-shape config and verify quickly:

- `scripts/run-jmx-parity.sh`
  - mTLS only endpoint enabled
  - default port `443` (configurable override for local non-root runs)
  - default sleep `5000ms` (configurable)
  - standalone mode set to `EchoRequestBody` (configurable)
  - cert setup reuse (`scripts/generate-mtls-certs.sh`)
  - explicit parameters:
    - `--port` (default: `443`)
    - `--sleep-ms` (default: `5000`)
    - `--connect-timeout-ms` (default: `60000`)
    - `--response-timeout-ms` (default: `60000`)

- `scripts/check-jmx-parity.sh`
  - send POST with unique correlation id
  - assert `200`
  - parse response JSON and assert same `correlationId`
  - run against .NET and Rust targets

### 3) Add JMeter CLI runner
Add `scripts/run-jmeter-testplan.sh` to execute `.temp/Test Plan.jmx` in non-GUI mode:

- pass keystore/truststore and passwords via JVM system properties
- pass test-shape parameters as JMeter properties (defaults = current JMX values):
  - `threads=1500`
  - `ramp_seconds=5`
  - `loops=5`
  - `connect_timeout_ms=60000`
  - `response_timeout_ms=60000`
  - `target_host` and `target_port` (defaults matching JMX parity profile)
- write logs/results under `.run-logs/jmeter/`
- parse result output for:
  - assertion failures
  - non-200 responses

Example shape (to adapt once JMeter is installed):

```bash
jmeter -n -t ".temp/Test Plan.jmx" \
  -l ".run-logs/jmeter/results.jtl" \
  -Jthreads=1500 \
  -Jramp_seconds=5 \
  -Jloops=5 \
  -Jconnect_timeout_ms=60000 \
  -Jresponse_timeout_ms=60000 \
  -Djavax.net.ssl.keyStoreType=PKCS12 \
  -Djavax.net.ssl.keyStore="$CLIENT_PFX" \
  -Djavax.net.ssl.keyStorePassword="$CLIENT_PFX_PASSWORD" \
  -Djavax.net.ssl.trustStore="$TRUSTSTORE_PATH" \
  -Djavax.net.ssl.trustStorePassword="$TRUSTSTORE_PASSWORD"
```

### 4) Upgrade `LiteGateway.LoadClient` to assert JMX-equivalent behavior
Add a JMX-parity client mode/profile so local verification can assert the same semantics as JMeter:

- request generation:
  - method configurable (default `POST` for this profile)
  - URL template with dynamic counter token in query (default format aligned to `${UiidC}`)
  - JSON body template with same dynamic token for `correlationId`
- assertion checks (same intent as JMX):
  - expected status code set (default: `200`)
  - JSONPath extraction + equality assertion (default: `$.correlationId == generated correlationId`)
  - explicit assertion failure counters + non-zero process exit when assertion failures occur
- load-shape defaults aligned to JMX but fully parameterized:
  - `--concurrency 1500`
  - `--ramp-seconds 5`
  - `--loops 5`
  - `--timeout 60`
  - `--max-request-time 60`

### 5) Documentation
Update `README.md` with:

- JMX parity mode/config values
- CLI parity-check command
- `LiteGateway.LoadClient` JMX-parity command and assertion outputs
- JMeter non-GUI command
- pass/fail criteria

## Verification gates

### Gate A: Fast CLI parity check (must pass first)
- .NET proxy: POST + correlation echo assertion passes
- Rust proxy: POST + correlation echo assertion passes

### Gate B: LoadClient JMX-parity check
- Execute `LiteGateway.LoadClient` in JMX-parity mode against .NET proxy.
- Execute `LiteGateway.LoadClient` in JMX-parity mode against Rust proxy.
- Require:
  - `200` status assertions pass
  - response JSONPath correlation assertions pass
  - zero assertion failures in summary + non-zero exit on failure

### Gate C: JMeter parity check
- Execute `.temp/Test Plan.jmx` non-GUI against .NET proxy
- Execute `.temp/Test Plan.jmx` non-GUI against Rust proxy
- Require:
  - response-code assertion pass
  - JSON extraction/assertion pass

### Gate D: Regression check
Re-run existing benchmark automation to ensure no regression:

- `./scripts/run-everything.sh --quick --proxy both`
- `./scripts/run-docker-matrix.sh --quick --proxy both`

## Acceptance criteria
The task is complete when:

1. Both proxies support a JMX-compatible mode that echoes request JSON (including `correlationId`).
2. JMX shape values are configurable parameters with documented defaults.
3. `LiteGateway.LoadClient` can assert the same status + correlation checks as JMX.
4. CLI parity checks pass on both implementations.
5. JMeter test plan assertions pass for both implementations.
6. Existing matrix benchmark workflows remain functional.
