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

DIRECTORY_PRIVATE_KEY="registro_participantes/directory-private.pem"
DIRECTORY_JWKS="registro_participantes/directory-jwks.json"

if [[ ! -f "$DIRECTORY_PRIVATE_KEY" ]]; then
  echo "ERROR: no existe la clave privada del Directorio: $DIRECTORY_PRIVATE_KEY" >&2
  exit 1
fi

if [[ ! -f "$DIRECTORY_JWKS" ]]; then
  echo "ERROR: no existe el JWKS del Directorio: $DIRECTORY_JWKS" >&2
  exit 1
fi

python3 <<'PY'
import base64, json, os, sys, time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
except ImportError:
    raise SystemExit("Instala cryptography: pip install cryptography")

keys = Path("registro_participantes")
priv_path = keys / "directory-private.pem"
jwks_path = keys / "directory-jwks.json"

priv = load_pem_private_key(priv_path.read_bytes(), password=None)

def require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"Variable requerida no definida: {name}")
    return value

def parse_redirect_uris(raw: str) -> list[str]:
    uris = [uri.strip() for uri in raw.split(",") if uri.strip()]
    if not uris:
        sys.exit("SSA_REDIRECT_URIS debe contener al menos una URI")
    return uris

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def validate_kid(kid: str) -> None:
    try:
        jwks = json.loads(jwks_path.read_text())
    except json.JSONDecodeError as exc:
        sys.exit(f"JWKS del Directorio inválido ({jwks_path}): {exc}")

    available = [
        key.get("kid")
        for key in jwks.get("keys", [])
        if isinstance(key, dict) and key.get("kid")
    ]
    if kid not in available:
        sys.exit(
            f"SSA_JWT_KID={kid!r} no está en {jwks_path}. kids disponibles: {available or '(ninguno)'}"
        )

software_id = require("SSA_SOFTWARE_ID")
jwt_kid = require("SSA_JWT_KID")
validate_kid(jwt_kid)

client_jwks = Path("client-jwks") / software_id / "jwks.json"
if not client_jwks.is_file():
    print(
        f"ADVERTENCIA: no existe {client_jwks}; ejecuta generate-client-jwks.sh antes del DCR",
        file=sys.stderr,
    )

claims = {
    "iss": require("SSA_ISSUER"),
    "iat": int(time.time()),
    "software_id": software_id,
    "organisation_id": require("SSA_ORGANISATION_ID"),
    "software_jwks_uri": require("SSA_SOFTWARE_JWKS_URI"),
    "software_client_name": require("SSA_SOFTWARE_CLIENT_NAME"),
    "redirect_uris": parse_redirect_uris(require("SSA_REDIRECT_URIS")),
    "software_version": require("SSA_SOFTWARE_VERSION"),
}
header = {"alg": "PS256", "kid": jwt_kid, "typ": "JWT"}
h = b64url(json.dumps(header, separators=(",", ":")).encode())
p = b64url(json.dumps(claims, separators=(",", ":")).encode())
signing_input = f"{h}.{p}".encode()
sig = priv.sign(
    signing_input,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
    hashes.SHA256(),
)
ssa = f"{h}.{p}.{b64url(sig)}"
out = keys / "sample-software-statement.jwt"
out.write_text(ssa)
print(ssa)
print(f"guardado en {out}", file=sys.stderr)
print(
    f"software_id={software_id} software_jwks_uri={claims['software_jwks_uri']}",
    file=sys.stderr,
)
PY
