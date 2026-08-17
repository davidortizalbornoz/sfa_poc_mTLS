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
CA_KEY="$CA_DIR/root-ca.key"
CA_CERT="$CA_DIR/root-ca.crt"

if [[ ! -f "$CA_KEY" || ! -f "$CA_CERT" ]]; then
  echo "ERROR: no se encontró CA raíz en $CA_DIR" >&2
  echo "Genera primero: ./scripts/generate-root-ca.sh" >&2
  exit 1
fi

python3 <<'PY'
import base64
import json
import os
import sys
import uuid
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
except ImportError:
    raise SystemExit("Instala cryptography: pip install cryptography")


def require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"Variable requerida no definida: {name}")
    return value


def b64url_int(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(byte_length, "big")).rstrip(b"=").decode()


software_id = require("SSA_SOFTWARE_ID")
out_dir = Path("client-jwks") / software_id
out_dir.mkdir(parents=True, exist_ok=True)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_numbers = private_key.public_key().public_numbers()
kid = f"{software_id.lower()}-{uuid.uuid4().hex[:12]}"

jwks = {
    "keys": [
        {
            "kid": kid,
            "kty": "RSA",
            "alg": "PS256",
            "use": "sig",
            "e": b64url_int(public_numbers.e),
            "n": b64url_int(public_numbers.n),
        }
    ]
}

private_pem = private_key.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
)
public_pem = private_key.public_key().public_bytes(
    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
)

(out_dir / "private.pem").write_bytes(private_pem)
(out_dir / "public.pem").write_bytes(public_pem)
(out_dir / "jwks.json").write_text(json.dumps(jwks, indent=2) + "\n")

print(out_dir / "jwks.json")
print(f"kid={kid}", file=sys.stderr)
print(f"signing_private_key={out_dir / 'private.pem'}", file=sys.stderr)
print(f"signing_public_key={out_dir / 'public.pem'}", file=sys.stderr)
PY

software_id="${SSA_SOFTWARE_ID:?SSA_SOFTWARE_ID requerido}"
out_dir="client-jwks/$software_id"

mtls_cn="${SSA_MTLS_CN:-$SSA_SOFTWARE_ID}"
mtls_org="${SSA_MTLS_ORGANIZATION:-${SSA_ORGANISATION_ID:-$SSA_SOFTWARE_ID}}"
mtls_days="${SSA_MTLS_VALIDITY_DAYS:-825}"
mtls_key_bits="${SSA_MTLS_KEY_BITS:-2048}"

if [[ -n "${SSA_MTLS_SAN_DNS:-}" ]]; then
  mtls_san_dns="$SSA_MTLS_SAN_DNS"
else
  mtls_san_dns="$(python3 - <<'PY'
import os
from urllib.parse import urlparse

uri = os.environ.get("SSA_SOFTWARE_JWKS_URI", "").strip()
if not uri:
    raise SystemExit("Define SSA_MTLS_SAN_DNS o SSA_SOFTWARE_JWKS_URI")
print(urlparse(uri).hostname or "")
PY
)"
fi

if [[ -z "$mtls_san_dns" ]]; then
  echo "ERROR: no se pudo derivar SAN DNS; define SSA_MTLS_SAN_DNS" >&2
  exit 1
fi

transport_key="$out_dir/transport.key"
transport_csr="$out_dir/transport.csr"
transport_crt="$out_dir/transport.crt"
transport_chain="$out_dir/transport-chain.crt"
ext_file="$(mktemp)"
trap 'rm -f "$ext_file"' EXIT

cat >"$ext_file" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:${mtls_san_dns}
EOF

openssl genrsa -out "$transport_key" "$mtls_key_bits" >/dev/null 2>&1

openssl req -new \
  -key "$transport_key" \
  -out "$transport_csr" \
  -subj "/CN=${mtls_cn}/O=${mtls_org}/C=CL" >/dev/null 2>&1

openssl x509 -req \
  -in "$transport_csr" \
  -CA "$CA_CERT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "$transport_crt" \
  -days "$mtls_days" \
  -sha256 \
  -extfile "$ext_file" >/dev/null 2>&1

cat "$transport_crt" "$CA_CERT" >"$transport_chain"
rm -f "$transport_csr"

echo "transport_key=$transport_key" >&2
echo "transport_cert=$transport_crt" >&2
echo "transport_chain=$transport_chain" >&2
echo "transport_san_dns=$mtls_san_dns" >&2
openssl x509 -in "$transport_crt" -noout -subject -issuer -dates -ext subjectAltName >&2
