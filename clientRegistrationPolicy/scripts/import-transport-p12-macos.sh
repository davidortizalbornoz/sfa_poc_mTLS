#!/usr/bin/env bash
# Importa transport.p12 + CA raíz en macOS para que Chrome/Safari presenten mTLS al gateway.
# Usa un llavero dedicado del POC (sin contraseña por defecto) para evitar prompts del
# llavero "Inicio de sesión" al seleccionar el certificado en Chrome.
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
  echo "Usando defaults de ssa.env.example" >&2
else
  echo "ERROR: no se encontró ssa.env" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: script solo para macOS" >&2
  exit 1
fi

CLIENT_ID="${1:-${SSA_SOFTWARE_ID:?SSA_SOFTWARE_ID requerido en ssa.env}}"
P12_PASSWORD="${P12_PASSWORD:-${SSA_MTLS_P12_PASSWORD:-changeit}}"
# Llavero dedicado dev: vacío = sin prompt de contraseña al usar la clave privada.
SFA_KEYCHAIN_NAME="${SFA_MTLS_KEYCHAIN_NAME:-sfa-mtls-poc.keychain}"
SFA_KEYCHAIN_PASSWORD="${SFA_MTLS_KEYCHAIN_PASSWORD:-}"
CA_DIR="${CA_DIR:-registro_participantes/ca}"
P12_FILE="${ROOT_DIR}/client-jwks/${CLIENT_ID}/transport.p12"
CA_CRT="${ROOT_DIR}/${CA_DIR}/root-ca.crt"
SFA_KEYCHAIN="${HOME}/Library/Keychains/${SFA_KEYCHAIN_NAME}-db"
LOGIN_KEYCHAIN="${HOME}/Library/Keychains/login.keychain-db"

if [[ ! -f "$P12_FILE" ]]; then
  echo "ERROR: no existe $P12_FILE" >&2
  echo "Genera primero: ./scripts/generate-transport-p12.sh" >&2
  exit 1
fi

if [[ ! -f "$CA_CRT" ]]; then
  echo "ERROR: no existe $CA_CRT" >&2
  exit 1
fi

echo "==> Llavero dedicado POC: ${SFA_KEYCHAIN_NAME} (dev, sin contraseña por defecto)"
if [[ ! -f "$SFA_KEYCHAIN" ]]; then
  security create-keychain -p "$SFA_KEYCHAIN_PASSWORD" "$SFA_KEYCHAIN_NAME"
fi
security unlock-keychain -p "$SFA_KEYCHAIN_PASSWORD" "$SFA_KEYCHAIN_NAME"
# Mantener desbloqueado en dev; no pedir contraseña al acceder a la clave privada.
security set-keychain-settings -u "$SFA_KEYCHAIN_NAME"

echo "==> Confiando CA raíz del POC"
security add-trusted-cert -d -r trustRoot -k "$SFA_KEYCHAIN_NAME" "$CA_CRT" 2>/dev/null || \
  security add-certificates -k "$SFA_KEYCHAIN_NAME" "$CA_CRT"

echo "==> Importando identidad mTLS (${CLIENT_ID})"
TRUST_ARGS=(-A)
for app in \
  "/Applications/Google Chrome.app" \
  "/Applications/Safari.app" \
  "/Applications/Firefox.app" \
  "/Applications/Arc.app" \
  "/Applications/Brave Browser.app"; do
  if [[ -d "$app" ]]; then
    TRUST_ARGS+=(-T "$app")
  fi
done

security import "$P12_FILE" -k "$SFA_KEYCHAIN_NAME" -P "$P12_PASSWORD" "${TRUST_ARGS[@]}"

echo "==> Permisos de clave privada para navegadores (sin prompt de llavero)"
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -k "$SFA_KEYCHAIN_PASSWORD" \
  "$SFA_KEYCHAIN_NAME"

echo "==> Priorizando llavero POC en búsqueda de certificados"
EXISTING_KEYCHAINS="$(security list-keychains -d user | tr -d '"')"
if ! echo "$EXISTING_KEYCHAINS" | grep -Fq "$SFA_KEYCHAIN"; then
  security list-keychains -d user -s "$SFA_KEYCHAIN" "$LOGIN_KEYCHAIN"
else
  security list-keychains -d user -s "$SFA_KEYCHAIN" \
    $(echo "$EXISTING_KEYCHAINS" | rg -v "sfa-mtls-poc.keychain" | tr '\n' ' ')
fi

echo ""
echo "Listo. Identidades SSL cliente (llavero ${SFA_KEYCHAIN_NAME}):"
security find-identity -v -p ssl-client "$SFA_KEYCHAIN_NAME" 2>/dev/null \
  | rg "${CLIENT_ID}|SFA mTLS|Finanzas Abiertas" \
  || security find-identity -v -p ssl-client "$SFA_KEYCHAIN_NAME"
echo ""
echo "Abre: https://sfa.localtest.me:8443/admin/master/console/"
echo "Certificado: ${SSA_SOFTWARE_CLIENT_NAME:-${CLIENT_ID} mTLS POC}"
echo "Cierra Chrome por completo (Cmd+Q) antes de probar."
echo "Login Keycloak: admin / admin_local_dev"
echo ""
echo "Nota: si antes importaste el mismo cert al llavero Inicio de sesión, elimínalo allí"
echo "      (Acceso a Llaveros) para evitar duplicados en el selector de Chrome."
