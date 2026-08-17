#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${SSA_ENV:-$ROOT_DIR/ssa.env}"

load_env() {
  local file="$1"
  if [[ -f "$file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
    return 0
  fi
  return 1
}

if load_env "$ENV_FILE"; then
  :
elif [[ "$ENV_FILE" != "$ROOT_DIR/ssa.env.example" ]] && load_env "$ROOT_DIR/ssa.env.example"; then
  echo "Usando defaults de ssa.env.example (copia a ssa.env para personalizar)" >&2
else
  echo "ERROR: no se encontró archivo de variables: $ENV_FILE" >&2
  echo "Copia ssa.env.example a ssa.env en clientRegistrationPolicy/" >&2
  exit 1
fi

CA_DIR="${CA_DIR:-registro_participantes/ca}"
CA_SUBJECT="${CA_SUBJECT:-/CN=SFA POC Root CA/O=Finanzas Abiertas POC/C=CL}"
CA_VALIDITY_DAYS="${CA_VALIDITY_DAYS:-3650}"
CA_KEY_BITS="${CA_KEY_BITS:-4096}"
FORCE="${FORCE:-0}"

CA_KEY="$CA_DIR/root-ca.key"
CA_CERT="$CA_DIR/root-ca.crt"
CA_SERIAL="$CA_DIR/root-ca.srl"

mkdir -p "$CA_DIR"

if [[ -f "$CA_KEY" || -f "$CA_CERT" ]]; then
  if [[ "$FORCE" != "1" ]]; then
    echo "ERROR: ya existen artefactos de CA en $CA_DIR" >&2
    echo "Usa FORCE=1 ./scripts/generate-root-ca.sh para regenerar (invalida certificados de clientes existentes)" >&2
    exit 1
  fi
  rm -f "$CA_KEY" "$CA_CERT" "$CA_SERIAL"
fi

openssl genrsa -out "$CA_KEY" "$CA_KEY_BITS" >/dev/null 2>&1

openssl req -x509 -new -nodes \
  -key "$CA_KEY" \
  -sha256 \
  -days "$CA_VALIDITY_DAYS" \
  -out "$CA_CERT" \
  -subj "$CA_SUBJECT" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1

echo "$CA_CERT"
echo "root_ca_key=$CA_KEY" >&2
echo "root_ca_cert=$CA_CERT" >&2
openssl x509 -in "$CA_CERT" -noout -subject -issuer -dates >&2
