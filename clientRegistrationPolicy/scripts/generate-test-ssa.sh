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
priv = load_pem_private_key(keys.joinpath("directory-private.pem").read_bytes(), password=None)

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

claims = {
    "iss": require("SSA_ISSUER"),
    "iat": int(time.time()),
    "software_id": require("SSA_SOFTWARE_ID"),
    "organisation_id": require("SSA_ORGANISATION_ID"),
    "software_jwks_uri": require("SSA_SOFTWARE_JWKS_URI"),
    "software_client_name": require("SSA_SOFTWARE_CLIENT_NAME"),
    "redirect_uris": parse_redirect_uris(require("SSA_REDIRECT_URIS")),
    "software_version": require("SSA_SOFTWARE_VERSION"),
}
header = {"alg": "PS256", "kid": require("SSA_JWT_KID"), "typ": "JWT"}
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
PY
