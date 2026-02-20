#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/certs/generated}"
PFX_PASSWORD="${MTLS_PFX_PASSWORD:-changeit}"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

CA_KEY="$OUT_DIR/ca.key.pem"
CA_CERT="$OUT_DIR/ca.cert.pem"
SERVER_KEY="$OUT_DIR/server.key.pem"
SERVER_CSR="$OUT_DIR/server.csr.pem"
SERVER_CERT="$OUT_DIR/server.cert.pem"
SERVER_PFX="$OUT_DIR/server.pfx"
CLIENT_KEY="$OUT_DIR/client.key.pem"
CLIENT_CSR="$OUT_DIR/client.csr.pem"
CLIENT_CERT="$OUT_DIR/client.cert.pem"
CLIENT_PFX="$OUT_DIR/client.pfx"
SERVER_EXT="$OUT_DIR/server.ext.cnf"
CLIENT_EXT="$OUT_DIR/client.ext.cnf"
ENV_SNIPPET="$OUT_DIR/mtls.env"

cat >"$SERVER_EXT" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyAgreement
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

cat >"$CLIENT_EXT" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyAgreement
extendedKeyUsage=clientAuth
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" -subj "/CN=LiteGateway-CA"

openssl ecparam -name prime256v1 -genkey -noout -out "$SERVER_KEY"
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -subj "/CN=localhost"
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 825 -sha256 -extfile "$SERVER_EXT"
openssl pkcs12 -export -out "$SERVER_PFX" -inkey "$SERVER_KEY" -in "$SERVER_CERT" -certfile "$CA_CERT" -password "pass:$PFX_PASSWORD"

openssl ecparam -name prime256v1 -genkey -noout -out "$CLIENT_KEY"
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=LiteGateway-Client"
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAserial "$OUT_DIR/ca.cert.srl" -out "$CLIENT_CERT" -days 825 -sha256 -extfile "$CLIENT_EXT"
openssl pkcs12 -export -out "$CLIENT_PFX" -inkey "$CLIENT_KEY" -in "$CLIENT_CERT" -certfile "$CA_CERT" -password "pass:$PFX_PASSWORD"

cat >"$ENV_SNIPPET" <<EOF
# source $ENV_SNIPPET
export LITEGATEWAY_Proxy__EnableHttp=true
export LITEGATEWAY_Proxy__HttpPort=8080
export LITEGATEWAY_Proxy__EnableHttps=true
export LITEGATEWAY_Proxy__HttpsPort=8443
export LITEGATEWAY_Proxy__EnableMtls=true
export LITEGATEWAY_Proxy__MtlsPort=9443
export LITEGATEWAY_Proxy__SleepDurationMs=5000
export LITEGATEWAY_Proxy__ServerCertificatePath="$SERVER_PFX"
export LITEGATEWAY_Proxy__ServerCertificatePassword="$PFX_PASSWORD"
export LITEGATEWAY_Proxy__TrustedCaPath="$CA_CERT"
export LITEGATEWAY_Proxy__OutboundClientCertificatePath="$CLIENT_PFX"
export LITEGATEWAY_Proxy__OutboundClientCertificatePassword="$PFX_PASSWORD"
export LITEGATEWAY_Proxy__UpstreamUrl=
export LITEGATEWAY_Proxy__PassConnectionClose=false
export CLIENT_CA_CERT="$CA_CERT"
export CLIENT_CERT_PEM="$CLIENT_CERT"
export CLIENT_KEY_PEM="$CLIENT_KEY"
export CLIENT_PFX="$CLIENT_PFX"
export CLIENT_PFX_PASSWORD="$PFX_PASSWORD"
EOF

rm -f "$SERVER_CSR" "$CLIENT_CSR" "$SERVER_EXT" "$CLIENT_EXT"

echo "Certificates written to: $OUT_DIR"
echo "Env snippet: $ENV_SNIPPET"
