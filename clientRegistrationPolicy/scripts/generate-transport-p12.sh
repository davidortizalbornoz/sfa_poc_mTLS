#!/usr/bin/env bash
# Genera transport.p12 compatible con Acceso a Llaveros (macOS).
# OpenSSL 3 por defecto usa AES-256; Keychain suele fallar con "contraseña incorrecta".
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

# Primer argumento opcional; por defecto el participante activo en ssa.env
CLIENT_ID="${1:-${SSA_SOFTWARE_ID:?SSA_SOFTWARE_ID requerido en ssa.env}}"
P12_PASSWORD="${P12_PASSWORD:-${SSA_MTLS_P12_PASSWORD:-changeit}}"
P12_FRIENDLY_NAME="${SSA_SOFTWARE_CLIENT_NAME:-${CLIENT_ID} mTLS POC}"

CA_DIR="${CA_DIR:-registro_participantes/ca}"
dir="client-jwks/${CLIENT_ID}"
transport_key="${dir}/transport.key"
transport_crt="${dir}/transport.crt"
ca_crt="${CA_DIR}/root-ca.crt"
out="${dir}/transport.p12"

for f in "$transport_key" "$transport_crt" "$ca_crt"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: no existe $f" >&2
    echo "Genera primero: ./scripts/generate-client-jwks.sh (SSA_SOFTWARE_ID=${CLIENT_ID} en ssa.env)" >&2
    exit 1
  fi
done

openssl pkcs12 -export \
  -out "$out" \
  -inkey "$transport_key" \
  -in "$transport_crt" \
  -certfile "$ca_crt" \
  -name "${P12_FRIENDLY_NAME}" \
  -passout "pass:${P12_PASSWORD}" \
  -keypbe PBE-SHA1-3DES \
  -certpbe PBE-SHA1-3DES \
  -macalg sha1

echo "Generado: $out"
echo "Participante (ssa.env): ${CLIENT_ID}"
echo "Password del .p12: ${P12_PASSWORD}"
echo ""
echo "macOS — importar para navegador (Chrome/Safari):"
echo "  ./scripts/import-transport-p12-macos.sh ${CLIENT_ID}"
echo ""
if [[ "${2:-}" == "--import" ]] || [[ "${IMPORT_P12:-}" == "1" ]]; then
  exec "$ROOT_DIR/scripts/import-transport-p12-macos.sh" "$CLIENT_ID"
fi
