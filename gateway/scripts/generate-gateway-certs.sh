#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_DIR="$ROOT_DIR/../clientRegistrationPolicy/registro_participantes/ca"
OUT_DIR="$ROOT_DIR/certs"
DAYS="${GATEWAY_CERT_DAYS:-825}"
KEY_BITS="${GATEWAY_KEY_BITS:-2048}"

CA_CERT="$CA_DIR/root-ca.crt"
CA_KEY="$CA_DIR/root-ca.key"

if [[ ! -f "$CA_CERT" || ! -f "$CA_KEY" ]]; then
  echo "ERROR: ejecuta primero clientRegistrationPolicy/scripts/generate-root-ca.sh" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

issue_server_cert() {
  local cn="$1"
  local san_dns="$2"
  local key="$OUT_DIR/${san_dns}.key"
  local csr="$OUT_DIR/${san_dns}.csr"
  local crt="$OUT_DIR/${san_dns}.crt"
  local ext
  ext="$(mktemp)"
  trap 'rm -f "$ext"' RETURN

  cat >"$ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${san_dns}
EOF

  openssl genrsa -out "$key" "$KEY_BITS" >/dev/null 2>&1
  openssl req -new -key "$key" -out "$csr" \
    -subj "/CN=${cn}/O=SFA mTLS POC Gateway/C=CL" >/dev/null 2>&1
  openssl x509 -req -in "$csr" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$crt" -days "$DAYS" -sha256 -extfile "$ext" >/dev/null 2>&1
  rm -f "$csr"

  echo "$crt"
}

SFA_CRT="$(issue_server_cert "sfa.localtest.me" "sfa.localtest.me")"
API_CRT="$(issue_server_cert "api.localtest.me" "api.localtest.me")"

cat "$SFA_CRT" "$CA_CERT" >"$OUT_DIR/sfa.localtest.me-chain.crt"
cat "$API_CRT" "$CA_CERT" >"$OUT_DIR/api.localtest.me-chain.crt"
cp "$CA_CERT" "$OUT_DIR/root-ca.crt"

echo "Certificados gateway generados en $OUT_DIR"
echo "  sfa.localtest.me -> $SFA_CRT"
echo "  api.localtest.me -> $API_CRT"
echo "  truststore clientes (mTLS) -> $OUT_DIR/root-ca.crt"
