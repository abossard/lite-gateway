#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${CERT_DIR:-$ROOT_DIR/certs/generated}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/.run-logs}"
PROXY_IMPL="both"
RUN_PROFILE="quick"
SKIP_BUILD=0
SKIP_CERTS=0
SLEEP_MS="${SLEEP_MS:-5000}"
PROXY_PID=""

usage() {
  cat <<'EOF'
Usage: ./scripts/run-everything.sh [options]

Runs cert generation, build, and matrix load tests against .NET and/or Rust proxies.

Options:
  --proxy <dotnet|rust|both>  Which proxy implementation(s) to run (default: both)
  --quick                      Fast matrix profile (default)
  --full                       Full matrix profile (load client defaults)
  --sleep-ms <int>             Proxy per-request sleep duration in ms (default: 5000)
  --skip-build                 Skip build steps
  --skip-certs                 Skip certificate regeneration (requires existing certs)
  -h, --help                   Show this help
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

ensure_ports_free() {
  local attempts="${1:-1}"
  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if ! is_port_busy 8080 && ! is_port_busy 8443 && ! is_port_busy 9443; then
      return 0
    fi
    sleep 1
  done

  echo "Required ports are in use (8080/8443/9443). Stop those listeners and retry." >&2
  lsof -nP -iTCP:8080 -sTCP:LISTEN || true
  lsof -nP -iTCP:8443 -sTCP:LISTEN || true
  lsof -nP -iTCP:9443 -sTCP:LISTEN || true
  exit 1
}

stop_proxy() {
  if [[ -n "${PROXY_PID}" ]]; then
    kill "${PROXY_PID}" 2>/dev/null || true
    wait "${PROXY_PID}" 2>/dev/null || true
    PROXY_PID=""
  fi
}

wait_for_endpoint() {
  local name="$1"
  shift

  local attempt
  for ((attempt = 1; attempt <= 40; attempt++)); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done

  echo "Timed out waiting for ${name} endpoint." >&2
  return 1
}

run_matrix_for_proxy() {
  local proxy_name="$1"
  shift
  local -a proxy_cmd=("$@")
  local proxy_log="$LOG_DIR/${proxy_name}-proxy.log"
  local matrix_log="$LOG_DIR/${proxy_name}-matrix.log"

  ensure_ports_free 3
  echo "===> Starting ${proxy_name} proxy"
  "${proxy_cmd[@]}" >"${proxy_log}" 2>&1 &
  PROXY_PID=$!

  wait_for_endpoint "HTTP" curl -sS -m 12 -f http://127.0.0.1:8080/ -o /dev/null
  wait_for_endpoint "HTTPS" curl -sS -m 12 -f --cacert "${CLIENT_CA_CERT}" https://127.0.0.1:8443/ -o /dev/null
  wait_for_endpoint "mTLS" curl -sS -m 12 -f --cacert "${CLIENT_CA_CERT}" --cert "${CLIENT_CERT_PEM}" --key "${CLIENT_KEY_PEM}" https://127.0.0.1:9443/ -o /dev/null

  echo "===> Running matrix against ${proxy_name} proxy"
  dotnet run --project "$ROOT_DIR/src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj" -c Release --no-build -- \
    --mode matrix \
    --cert-pfx "${CLIENT_PFX}" \
    --cert-password "${CLIENT_PFX_PASSWORD}" \
    --custom-ca "${CLIENT_CA_CERT}" \
    "${MATRIX_ARGS[@]}" | tee "${matrix_log}"

  stop_proxy
  ensure_ports_free 10

  echo "===> ${proxy_name} matrix summary"
  awk '/^=== Matrix Autotune Summary ===/{print; flag=1; next} flag{print}' "${matrix_log}"
  echo
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy)
      PROXY_IMPL="${2:-}"
      shift 2
      ;;
    --quick)
      RUN_PROFILE="quick"
      shift
      ;;
    --full)
      RUN_PROFILE="full"
      shift
      ;;
    --sleep-ms)
      SLEEP_MS="${2:-}"
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

if [[ ! "${SLEEP_MS}" =~ ^[0-9]+$ ]]; then
  echo "--sleep-ms must be a non-negative integer." >&2
  exit 1
fi

require_cmd dotnet
require_cmd cargo
require_cmd curl
require_cmd lsof
require_cmd awk
require_cmd tee

trap stop_proxy EXIT INT TERM
mkdir -p "${LOG_DIR}"

if ((SKIP_CERTS == 0)); then
  "$ROOT_DIR/scripts/generate-mtls-certs.sh" "${CERT_DIR}"
fi

ENV_FILE="${CERT_DIR}/mtls.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing certificate env file: ${ENV_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"

: "${CLIENT_PFX:?CLIENT_PFX missing from cert env}"
: "${CLIENT_PFX_PASSWORD:?CLIENT_PFX_PASSWORD missing from cert env}"
: "${CLIENT_CA_CERT:?CLIENT_CA_CERT missing from cert env}"
: "${CLIENT_CERT_PEM:?CLIENT_CERT_PEM missing from cert env}"
: "${CLIENT_KEY_PEM:?CLIENT_KEY_PEM missing from cert env}"

export LITEGATEWAY_Proxy__EnableHttp=true
export LITEGATEWAY_Proxy__HttpPort=8080
export LITEGATEWAY_Proxy__EnableHttps=true
export LITEGATEWAY_Proxy__HttpsPort=8443
export LITEGATEWAY_Proxy__EnableMtls=true
export LITEGATEWAY_Proxy__MtlsPort=9443
export LITEGATEWAY_Proxy__SleepDurationMs="${SLEEP_MS}"

if ((SKIP_BUILD == 0)); then
  echo "===> Building .NET proxy and load client (Release)"
  dotnet build "$ROOT_DIR/src/LiteGateway.Proxy/LiteGateway.Proxy.csproj" -c Release --nologo --verbosity minimal >/dev/null
  dotnet build "$ROOT_DIR/src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj" -c Release --nologo --verbosity minimal >/dev/null

  if [[ "${PROXY_IMPL}" == "rust" || "${PROXY_IMPL}" == "both" ]]; then
    echo "===> Building Rust proxy (Release)"
    cargo build --manifest-path "$ROOT_DIR/src/LiteGateway.Proxy.Rust/Cargo.toml" --release --quiet
  fi
fi

declare -a MATRIX_ARGS=()
if [[ "${RUN_PROFILE}" == "quick" ]]; then
  MATRIX_ARGS=(
    --matrix-run-duration 8
    --autotune-min-concurrency 64
    --autotune-max-concurrency 512
    --autotune-growth-factor 2
    --autotune-max-error-pct 2
    --autotune-binary-steps 0
  )
fi

echo "===> Run profile: ${RUN_PROFILE}"
echo "===> Logs: ${LOG_DIR}"

if [[ "${PROXY_IMPL}" == "dotnet" || "${PROXY_IMPL}" == "both" ]]; then
  run_matrix_for_proxy "dotnet" \
    dotnet run --project "$ROOT_DIR/src/LiteGateway.Proxy/LiteGateway.Proxy.csproj" -c Release --no-build
fi

if [[ "${PROXY_IMPL}" == "rust" || "${PROXY_IMPL}" == "both" ]]; then
  run_matrix_for_proxy "rust" \
    cargo run --manifest-path "$ROOT_DIR/src/LiteGateway.Proxy.Rust/Cargo.toml" --release --quiet
fi

echo "Done."
