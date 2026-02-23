#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_PATH="${PLAN_PATH:-$ROOT_DIR/specs/jmeter/TestPlan.jmx}"
CERT_DIR="${CERT_DIR:-$ROOT_DIR/certs/generated}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/.run-logs/jmeter}"
PROXY_IMPL="both"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-9443}"
TRUSTSTORE_PASSWORD="${TRUSTSTORE_PASSWORD:-changeit}"
SLEEP_MS="${SLEEP_MS:-5000}"
HIGH_SCALE=0
THREADS_OVERRIDE=""
RAMP_SECONDS_OVERRIDE=""
LOOPS_OVERRIDE=""
CONNECT_TIMEOUT_MS_OVERRIDE=""
RESPONSE_TIMEOUT_MS_OVERRIDE=""
SKIP_BUILD=0
SKIP_CERTS=0
PROXY_PID=""

usage() {
  cat <<'EOF'
Usage: ./scripts/run-jmeter-testplan.sh [options]

Runs specs/jmeter/TestPlan.jmx in non-GUI mode against the .NET and/or Rust proxy
with mTLS client certs, and validates there are zero failed samples.

Options:
  --proxy <dotnet|rust|both>  Proxy implementation(s) to test (default: both)
  --host <hostname>           Target host used in runtime test plan (default: 127.0.0.1)
  --port <int>                mTLS target port (default: 9443)
  --plan <path>               JMeter test plan path (default: specs/jmeter/TestPlan.jmx)
  --sleep-ms <int>            Proxy async sleep duration in ms (default: 5000)
  --high-scale                Use high-scale load defaults (12000 threads, 30s ramp, 10 loops, 120s timeouts)
  --threads <int>             Override thread count (virtual users)
  --ramp-seconds <int>        Override ramp-up duration in seconds
  --loops <int>               Override loop count per virtual user
  --connect-timeout-ms <int>  Override HTTP connect timeout in milliseconds
  --response-timeout-ms <int> Override HTTP response timeout in milliseconds
  --skip-build                Skip proxy build steps
  --skip-certs                Skip certificate regeneration
  -h, --help                  Show this help
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

is_port_busy() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

wait_for_endpoint() {
  local name="$1"
  shift

  local attempt
  for ((attempt = 1; attempt <= 120; attempt++)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.4
  done

  echo "Timed out waiting for ${name} endpoint." >&2
  return 1
}

stop_proxy() {
  if [[ -n "${PROXY_PID}" ]]; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
    PROXY_PID=""
  fi
}

prepare_runtime_plan() {
  local output_path="$1"
  sed \
    -e "s|<intProp name=\"ThreadGroup.num_threads\">[^<]*</intProp>|<intProp name=\"ThreadGroup.num_threads\">${THREADS}</intProp>|" \
    -e "s|<intProp name=\"ThreadGroup.ramp_time\">[^<]*</intProp>|<intProp name=\"ThreadGroup.ramp_time\">${RAMP_SECONDS}</intProp>|" \
    -e "s|<stringProp name=\"LoopController.loops\">[^<]*</stringProp>|<stringProp name=\"LoopController.loops\">${LOOPS}</stringProp>|" \
    -e "s|<intProp name=\"HTTPSampler.connect_timeout\">[^<]*</intProp>|<intProp name=\"HTTPSampler.connect_timeout\">${CONNECT_TIMEOUT_MS}</intProp>|" \
    -e "s|<intProp name=\"HTTPSampler.response_timeout\">[^<]*</intProp>|<intProp name=\"HTTPSampler.response_timeout\">${RESPONSE_TIMEOUT_MS}</intProp>|" \
    -e "s|<stringProp name=\"HTTPSampler.domain\">[^<]*</stringProp>|<stringProp name=\"HTTPSampler.domain\">${TARGET_HOST}</stringProp>|" \
    -e "s|<stringProp name=\"HTTPSampler.port\">[^<]*</stringProp>|<stringProp name=\"HTTPSampler.port\">${TARGET_PORT}</stringProp>|" \
    "$PLAN_PATH" >"$output_path"
}

prepare_truststore() {
  local truststore_path="$1"
  rm -f "$truststore_path"
  keytool -importcert -noprompt \
    -alias litegateway-ca \
    -file "$CLIENT_CA_CERT" \
    -keystore "$truststore_path" \
    -storetype PKCS12 \
    -storepass "$TRUSTSTORE_PASSWORD" >/dev/null
}

validate_jtl() {
  local jtl_path="$1"
  python3 - "$jtl_path" <<'PY'
import csv
import sys

jtl_path = sys.argv[1]
total = 0
failed = 0
assertion_failed = 0

with open(jtl_path, newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    if not reader.fieldnames:
        print("JTL parse error: missing header row")
        sys.exit(2)

    success_key = next((name for name in reader.fieldnames if name.strip().lower() == "success"), None)
    failure_key = next((name for name in reader.fieldnames if name.strip().lower() == "failuremessage"), None)
    if success_key is None:
        print("JTL parse error: success column not found")
        sys.exit(2)

    for row in reader:
        total += 1
        is_success = str(row.get(success_key, "")).strip().lower() == "true"
        if not is_success:
            failed += 1
        failure_message = str(row.get(failure_key, "")).strip() if failure_key else ""
        if failure_message:
            assertion_failed += 1

print(f"total={total} failed={failed} assertion_failed={assertion_failed}")
sys.exit(1 if failed > 0 or assertion_failed > 0 else 0)
PY
}

run_for_proxy() {
  local proxy_name="$1"
  shift
  local -a proxy_cmd=("$@")

  local run_dir="$LOG_DIR/$proxy_name"
  local runtime_plan="$run_dir/test-plan.runtime.jmx"
  local truststore="$run_dir/truststore.p12"
  local jtl_file="$run_dir/results.csv"
  local summary_file="$run_dir/summary.txt"
  local jmeter_stdout="$run_dir/jmeter.stdout.log"
  local jmeter_log="$run_dir/jmeter.log"
  local proxy_log="$run_dir/proxy.log"
  mkdir -p "$run_dir"
  rm -f "$runtime_plan" "$truststore" "$jtl_file" "$summary_file" "$jmeter_stdout" "$jmeter_log" "$proxy_log"

  if is_port_busy "$TARGET_PORT"; then
    echo "Target port ${TARGET_PORT} is already in use. Stop listeners and retry." >&2
    lsof -nP -iTCP:"$TARGET_PORT" -sTCP:LISTEN || true
    return 1
  fi

  prepare_runtime_plan "$runtime_plan"
  prepare_truststore "$truststore"

  echo "===> Starting ${proxy_name} proxy on port ${TARGET_PORT}"
  "${proxy_cmd[@]}" >"$proxy_log" 2>&1 &
  PROXY_PID=$!

  wait_for_endpoint "${proxy_name} mTLS" \
    curl -sS -m 12 -f --cacert "$CLIENT_CA_CERT" --cert "$CLIENT_CERT_PEM" --key "$CLIENT_KEY_PEM" "https://${TARGET_HOST}:${TARGET_PORT}/" -o /dev/null

  echo "===> Running JMeter test plan for ${proxy_name}"
  set +e
  jmeter -n -t "$runtime_plan" -l "$jtl_file" -j "$jmeter_log" \
    -Djavax.net.ssl.keyStore="$CLIENT_PFX" \
    -Djavax.net.ssl.keyStorePassword="$CLIENT_PFX_PASSWORD" \
    -Djavax.net.ssl.keyStoreType=PKCS12 \
    -Djavax.net.ssl.trustStore="$truststore" \
    -Djavax.net.ssl.trustStorePassword="$TRUSTSTORE_PASSWORD" \
    -Djavax.net.ssl.trustStoreType=PKCS12 \
    -Jjmeter.save.saveservice.output_format=csv \
    -Jjmeter.save.saveservice.print_field_names=true \
    -Jjmeter.save.saveservice.successful=true \
    -Jjmeter.save.saveservice.assertion_results_failure_message=true \
    >"$jmeter_stdout" 2>&1
  local jmeter_exit_code=$?
  set -e

  if ((jmeter_exit_code != 0)); then
    echo "JMeter failed for ${proxy_name} (exit ${jmeter_exit_code}). See ${jmeter_stdout} and ${jmeter_log}." >&2
    tail -n 40 "$jmeter_stdout" >&2 || true
    stop_proxy
    return "$jmeter_exit_code"
  fi

  if ! validate_jtl "$jtl_file" | tee "$summary_file"; then
    echo "JMeter assertions failed for ${proxy_name}. See ${summary_file} and ${jtl_file}." >&2
    stop_proxy
    return 1
  fi

  stop_proxy
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy)
      PROXY_IMPL="${2:-}"
      shift 2
      ;;
    --host)
      TARGET_HOST="${2:-}"
      shift 2
      ;;
    --port)
      TARGET_PORT="${2:-}"
      shift 2
      ;;
    --plan)
      PLAN_PATH="${2:-}"
      shift 2
      ;;
    --sleep-ms)
      SLEEP_MS="${2:-}"
      shift 2
      ;;
    --high-scale)
      HIGH_SCALE=1
      shift
      ;;
    --threads)
      THREADS_OVERRIDE="${2:-}"
      shift 2
      ;;
    --ramp-seconds)
      RAMP_SECONDS_OVERRIDE="${2:-}"
      shift 2
      ;;
    --loops)
      LOOPS_OVERRIDE="${2:-}"
      shift 2
      ;;
    --connect-timeout-ms)
      CONNECT_TIMEOUT_MS_OVERRIDE="${2:-}"
      shift 2
      ;;
    --response-timeout-ms)
      RESPONSE_TIMEOUT_MS_OVERRIDE="${2:-}"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-certs)
      SKIP_CERTS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "${PROXY_IMPL}" != "dotnet" && "${PROXY_IMPL}" != "rust" && "${PROXY_IMPL}" != "both" ]]; then
  echo "--proxy must be dotnet, rust, or both." >&2
  exit 1
fi

if ((HIGH_SCALE == 1)); then
  DEFAULT_THREADS=12000
  DEFAULT_RAMP_SECONDS=30
  DEFAULT_LOOPS=10
  DEFAULT_CONNECT_TIMEOUT_MS=120000
  DEFAULT_RESPONSE_TIMEOUT_MS=120000
else
  DEFAULT_THREADS=1500
  DEFAULT_RAMP_SECONDS=5
  DEFAULT_LOOPS=5
  DEFAULT_CONNECT_TIMEOUT_MS=60000
  DEFAULT_RESPONSE_TIMEOUT_MS=60000
fi

THREADS="${THREADS_OVERRIDE:-$DEFAULT_THREADS}"
RAMP_SECONDS="${RAMP_SECONDS_OVERRIDE:-$DEFAULT_RAMP_SECONDS}"
LOOPS="${LOOPS_OVERRIDE:-$DEFAULT_LOOPS}"
CONNECT_TIMEOUT_MS="${CONNECT_TIMEOUT_MS_OVERRIDE:-$DEFAULT_CONNECT_TIMEOUT_MS}"
RESPONSE_TIMEOUT_MS="${RESPONSE_TIMEOUT_MS_OVERRIDE:-$DEFAULT_RESPONSE_TIMEOUT_MS}"

if [[ ! "${TARGET_PORT}" =~ ^[0-9]+$ ]] || ((TARGET_PORT < 1 || TARGET_PORT > 65535)); then
  echo "--port must be a valid TCP port." >&2
  exit 1
fi

if [[ ! "${SLEEP_MS}" =~ ^[0-9]+$ ]]; then
  echo "--sleep-ms must be a non-negative integer." >&2
  exit 1
fi

if [[ ! "${THREADS}" =~ ^[0-9]+$ ]] || ((THREADS < 1 || THREADS > 500000)); then
  echo "--threads must be between 1 and 500000." >&2
  exit 1
fi

if [[ ! "${RAMP_SECONDS}" =~ ^[0-9]+$ ]] || ((RAMP_SECONDS < 1 || RAMP_SECONDS > 86400)); then
  echo "--ramp-seconds must be between 1 and 86400." >&2
  exit 1
fi

if [[ ! "${LOOPS}" =~ ^[0-9]+$ ]] || ((LOOPS < 1 || LOOPS > 1000000)); then
  echo "--loops must be between 1 and 1000000." >&2
  exit 1
fi

if [[ ! "${CONNECT_TIMEOUT_MS}" =~ ^[0-9]+$ ]] || ((CONNECT_TIMEOUT_MS < 1000 || CONNECT_TIMEOUT_MS > 600000)); then
  echo "--connect-timeout-ms must be between 1000 and 600000." >&2
  exit 1
fi

if [[ ! "${RESPONSE_TIMEOUT_MS}" =~ ^[0-9]+$ ]] || ((RESPONSE_TIMEOUT_MS < 1000 || RESPONSE_TIMEOUT_MS > 600000)); then
  echo "--response-timeout-ms must be between 1000 and 600000." >&2
  exit 1
fi

if [[ ! -f "$PLAN_PATH" ]]; then
  echo "JMeter plan not found: $PLAN_PATH" >&2
  exit 1
fi

require_cmd dotnet
require_cmd cargo
require_cmd curl
require_cmd lsof
require_cmd sed
require_cmd keytool
require_cmd python3
require_cmd jmeter

mkdir -p "$LOG_DIR"
trap stop_proxy EXIT INT TERM

if ((SKIP_CERTS == 0)); then
  "$ROOT_DIR/scripts/generate-mtls-certs.sh" "$CERT_DIR"
fi

ENV_FILE="$CERT_DIR/mtls.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing certificate env file: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

: "${CLIENT_PFX:?CLIENT_PFX missing from cert env}"
: "${CLIENT_PFX_PASSWORD:?CLIENT_PFX_PASSWORD missing from cert env}"
: "${CLIENT_CA_CERT:?CLIENT_CA_CERT missing from cert env}"
: "${CLIENT_CERT_PEM:?CLIENT_CERT_PEM missing from cert env}"
: "${CLIENT_KEY_PEM:?CLIENT_KEY_PEM missing from cert env}"

if ((SKIP_BUILD == 0)); then
  if [[ "$PROXY_IMPL" == "dotnet" || "$PROXY_IMPL" == "both" ]]; then
    echo "===> Building .NET proxy (Release)"
    dotnet build "$ROOT_DIR/src/LiteGateway.Proxy/LiteGateway.Proxy.csproj" -c Release --nologo --verbosity minimal >/dev/null
  fi

  if [[ "$PROXY_IMPL" == "rust" || "$PROXY_IMPL" == "both" ]]; then
    echo "===> Building Rust proxy (Release)"
    cargo build --manifest-path "$ROOT_DIR/src/LiteGateway.Proxy.Rust/Cargo.toml" --release --quiet
  fi
fi

export LITEGATEWAY_Proxy__EnableHttp=false
export LITEGATEWAY_Proxy__EnableHttps=false
export LITEGATEWAY_Proxy__EnableMtls=true
export LITEGATEWAY_Proxy__MtlsPort="$TARGET_PORT"
export LITEGATEWAY_Proxy__SleepDurationMs="$SLEEP_MS"
export LITEGATEWAY_RustProxy__EnableHttp=false
export LITEGATEWAY_RustProxy__EnableHttps=false
export LITEGATEWAY_RustProxy__EnableMtls=true
export LITEGATEWAY_RustProxy__MtlsPort="$TARGET_PORT"
export LITEGATEWAY_RustProxy__SleepDurationMs="$SLEEP_MS"

echo "===> Runtime JMeter params: threads=${THREADS} ramp=${RAMP_SECONDS}s loops=${LOOPS} connect_timeout=${CONNECT_TIMEOUT_MS}ms response_timeout=${RESPONSE_TIMEOUT_MS}ms"

if [[ "$PROXY_IMPL" == "dotnet" || "$PROXY_IMPL" == "both" ]]; then
  run_for_proxy "dotnet" dotnet run --project "$ROOT_DIR/src/LiteGateway.Proxy/LiteGateway.Proxy.csproj" -c Release --no-build
fi

if [[ "$PROXY_IMPL" == "rust" || "$PROXY_IMPL" == "both" ]]; then
  run_for_proxy "rust" cargo run --manifest-path "$ROOT_DIR/src/LiteGateway.Proxy.Rust/Cargo.toml" --release --quiet
fi

echo "Done. Logs: $LOG_DIR"
