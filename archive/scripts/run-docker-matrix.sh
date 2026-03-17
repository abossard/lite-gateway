#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
CERT_DIR="${CERT_DIR:-$ROOT_DIR/certs/generated}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/.run-logs/docker}"
PROXY_IMPL="both"
RUN_PROFILE="quick"
SKIP_BUILD=0
SKIP_CERTS=0
SKIP_IMAGE_BUILD=0
SLEEP_MS="${SLEEP_MS:-5000}"
COMPOSE_STARTED=0

usage() {
  cat <<'EOF'
Usage: ./scripts/run-docker-matrix.sh [options]

Builds and runs the .NET and/or Rust proxies in Docker, then runs matrix load tests
from the host load client against each containerized proxy.

Options:
  --proxy <dotnet|rust|both>  Which proxy implementation(s) to test (default: both)
  --quick                      Fast matrix profile (default)
  --full                       Full matrix profile (load client defaults)
  --sleep-ms <int>             Proxy per-request sleep duration in ms (default: 5000)
  --skip-build                 Skip host load client build
  --skip-certs                 Skip certificate regeneration (requires existing certs)
  --skip-image-build           Skip docker compose build
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
  local ports=("$@")
  local port
  for port in "${ports[@]}"; do
    if is_port_busy "$port"; then
      echo "Required port is already in use: ${port}" >&2
      lsof -nP -iTCP:"${port}" -sTCP:LISTEN || true
      exit 1
    fi
  done
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

cleanup() {
  if ((COMPOSE_STARTED == 1)); then
    docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
  fi
}

run_matrix_for_target() {
  local proxy_name="$1"
  local http_port="$2"
  local https_port="$3"
  local mtls_port="$4"
  local matrix_log="$LOG_DIR/${proxy_name}-docker-matrix.log"

  wait_for_endpoint "${proxy_name} HTTP" curl -sS -m 12 -f "http://127.0.0.1:${http_port}/" -o /dev/null
  wait_for_endpoint "${proxy_name} HTTPS" curl -sS -m 12 -f --cacert "${CLIENT_CA_CERT}" "https://127.0.0.1:${https_port}/" -o /dev/null
  wait_for_endpoint "${proxy_name} mTLS" curl -sS -m 12 -f --cacert "${CLIENT_CA_CERT}" --cert "${CLIENT_CERT_PEM}" --key "${CLIENT_KEY_PEM}" "https://127.0.0.1:${mtls_port}/" -o /dev/null

  echo "===> Running matrix against ${proxy_name} Docker proxy"
  dotnet run --project "$ROOT_DIR/src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj" -c Release --no-build -- \
    --mode matrix \
    --cert-pfx "${CLIENT_PFX}" \
    --cert-password "${CLIENT_PFX_PASSWORD}" \
    --custom-ca "${CLIENT_CA_CERT}" \
    --matrix-http-url "http://localhost:${http_port}/" \
    --matrix-https-url "https://localhost:${https_port}/" \
    --matrix-mtls-url "https://localhost:${mtls_port}/" \
    "${MATRIX_ARGS[@]}" | tee "${matrix_log}"

  echo "===> ${proxy_name} Docker matrix summary"
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
    --skip-image-build)
      SKIP_IMAGE_BUILD=1
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

require_cmd docker
require_cmd dotnet
require_cmd curl
require_cmd lsof
require_cmd awk
require_cmd tee

mkdir -p "$LOG_DIR"
trap cleanup EXIT INT TERM

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

if ((SKIP_BUILD == 0)); then
  echo "===> Building host load client (Release)"
  dotnet build "$ROOT_DIR/src/LiteGateway.LoadClient/LiteGateway.LoadClient.csproj" -c Release --nologo --verbosity minimal >/dev/null
fi

declare -a SERVICES=()
declare -a REQUIRED_PORTS=()
if [[ "${PROXY_IMPL}" == "dotnet" || "${PROXY_IMPL}" == "both" ]]; then
  SERVICES+=("dotnet-proxy")
  REQUIRED_PORTS+=(18080 18443 19443)
fi
if [[ "${PROXY_IMPL}" == "rust" || "${PROXY_IMPL}" == "both" ]]; then
  SERVICES+=("rust-proxy")
  REQUIRED_PORTS+=(28080 28443 29443)
fi

ensure_ports_free "${REQUIRED_PORTS[@]}"

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

export CLIENT_PFX_PASSWORD
export LITEGATEWAY_PROXY_SLEEP_MS="${SLEEP_MS}"

if ((SKIP_IMAGE_BUILD == 0)); then
  echo "===> Building Docker images (${SERVICES[*]})"
  docker compose -f "$COMPOSE_FILE" build "${SERVICES[@]}"
fi

echo "===> Starting Docker services (${SERVICES[*]})"
docker compose -f "$COMPOSE_FILE" up -d "${SERVICES[@]}"
COMPOSE_STARTED=1

if [[ "${PROXY_IMPL}" == "dotnet" || "${PROXY_IMPL}" == "both" ]]; then
  run_matrix_for_target "dotnet" 18080 18443 19443
fi

if [[ "${PROXY_IMPL}" == "rust" || "${PROXY_IMPL}" == "both" ]]; then
  run_matrix_for_target "rust" 28080 28443 29443
fi

echo "Done. Logs: ${LOG_DIR}"
