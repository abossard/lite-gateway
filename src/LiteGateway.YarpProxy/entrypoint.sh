#!/bin/sh
# =============================================================================
# Entrypoint: Translates PROXY_HEADER_* env vars to YARP config env vars
# =============================================================================
# This enables dynamic header injection without changing the Docker image.
#
# Usage:  PROXY_HEADER_TEST_ID=1234
#   → sets YARP transform: RequestHeader "TEST-ID" with value "1234"
#
# The env var name after PROXY_HEADER_ is converted: underscores → hyphens.
# So PROXY_HEADER_TEST_ID → header "TEST-ID"
#    PROXY_HEADER_X_CORRELATION_ID → header "X-CORRELATION-ID"
#
# This handles the requirement where the external env var name changes
# (e.g., TEST_123_ID vs TEST_456_ID) — the operator simply sets:
#   PROXY_HEADER_TEST_ID=$TEST_123_ID   (or $TEST_456_ID)
# in the docker-compose/k8s manifest. The image stays the same.
# =============================================================================

idx=0
for var in $(env | grep '^PROXY_HEADER_' | sort); do
  key=$(echo "$var" | cut -d= -f1)
  value=$(echo "$var" | cut -d= -f2-)
  header_name=$(echo "$key" | sed 's/^PROXY_HEADER_//' | tr '_' '-')

  export "ReverseProxy__Routes__catch-all__Transforms__${idx}__RequestHeader=${header_name}"
  export "ReverseProxy__Routes__catch-all__Transforms__${idx}__Set=${value}"
  idx=$((idx + 1))
done

exec /app/LiteGateway.YarpProxy "$@"
