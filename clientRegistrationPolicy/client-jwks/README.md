# client-jwks/ — material criptográfico del TPP

Cada subcarpeta `{SOFTWARE_ID}/` contiene las claves y certificados de un **Third Party Provider (TPP)** registrado en el POC. El nombre de la carpeta coincide con `SSA_SOFTWARE_ID` en `ssa.env`.

Generación:

```bash
# Desde clientRegistrationPolicy/, con SSA_SOFTWARE_ID=LIDER-BCI en ssa.env
./scripts/generate-client-jwks.sh
# → client-jwks/LIDER-BCI/
```

Requisito previo: CA raíz en `registro_participantes/ca/` (`./scripts/generate-root-ca.sh`).

Documentación general: [`../README.md`](../README.md).

---

## Estructura por TPP

```
client-jwks/
└── LIDER-BCI/                    ← SSA_SOFTWARE_ID
    ├── jwks.json                 ← público: JWKS para DCR / OAuth
    ├── public.pem                ← público: clave RSA de firma (PEM)
    ├── private.pem               ← SECRETO: firma JWS
    ├── transport.crt             ← público: certificado mTLS cliente
    ├── transport-chain.crt       ← público: cert + CA raíz
    └── transport.key             ← SECRETO: clave privada mTLS
```

---

## Firma JWS — capa aplicación

Material para **JSON Web Signature** en flujos OAuth 2.0 / OpenID Connect (FAPI). El Authorization Server **verifica** con `jwks.json`; el TPP **firma** con `private.pem`.

| Archivo | Formato | Propósito | Consumidor |
|---|---|---|---|
| **`jwks.json`** | JWKS (JSON) | Publica la clave pública RSA con `kid`, `alg: PS256`, `use: sig`. Es lo que declaras en `software_jwks_uri` / `jwks_uri` durante el DCR. | Authorization Server (descarga y cachea) |
| **`public.pem`** | RSA SPKI (PEM) | Representación PEM de la misma clave pública del JWKS. Respaldo para configuraciones que exigen PEM en lugar de JWKS. | Integraciones locales, depuración |
| **`private.pem`** | RSA PKCS#8 (PEM) | Clave privada del TPP. Firma JWTs como client assertion (`private_key_jwt`), request object u otros JWS. | Aplicación del TPP |

### Usos típicos de la clave de firma

- **Client authentication** con `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- **Request Object** firmado en flujos FAPI
- Cualquier JWS donde el AS espere `alg: PS256` y el `kid` publicado en el JWKS

### Lo que NO hace

- No firma certificados X.509
- No se usa en el handshake TLS
- No sustituye al SSA (el SSA lo firma el **Directorio**, no el TPP)

---

## Transporte mTLS — capa TLS

Material para **autenticación mutua TLS** (`tls_client_auth`). Certificado emitido por la CA raíz del POC (`registro_participantes/ca/root-ca.crt`).

| Archivo | Formato | Propósito | Consumidor |
|---|---|---|---|
| **`transport.key`** | RSA (PEM) | Clave privada del certificado de cliente TLS. Se presenta junto con `transport.crt` en conexiones HTTPS. | Cliente HTTP del TPP (curl, Java SSLContext, etc.) |
| **`transport.crt`** | X.509 (PEM) | Certificado de cliente con `extendedKeyUsage: clientAuth`. Identifica al TPP en la capa de transporte. | Authorization Server / API Gateway (valida contra CA raíz) |
| **`transport-chain.crt`** | Cadena PEM | Concatenación `transport.crt` + `root-ca.crt`. Útil cuando el servidor o herramienta exige enviar la cadena completa. | Cliente TLS, pruebas manuales |

### Atributos del certificado

Derivados de `ssa.env` al ejecutar el script:

| Atributo X.509 | Origen |
|---|---|
| `CN` (Common Name) | `SSA_MTLS_CN` → default `SSA_SOFTWARE_ID` |
| `O` (Organization) | `SSA_MTLS_ORGANIZATION` → default `SSA_ORGANISATION_ID` |
| `C=CL` | Fijo en el script |
| `subjectAltName` (DNS) | `SSA_MTLS_SAN_DNS` → default hostname de `SSA_SOFTWARE_JWKS_URI` |
| Emisor (`issuer`) | CN del certificado CA raíz |
| Vigencia | `SSA_MTLS_VALIDITY_DAYS` (default 825 días) |

### Verificación local

```bash
openssl verify -CAfile ../registro_participantes/ca/root-ca.crt \
  LIDER-BCI/transport.crt

openssl x509 -in LIDER-BCI/transport.crt -noout -text
```

---

## Regeneración y múltiples TPPs

Cada ejecución de `generate-client-jwks.sh` **sobrescribe** la carpeta del `SSA_SOFTWARE_ID` actual:

- Nuevo `kid` en `jwks.json`
- Nuevas claves RSA de firma y transporte
- Nuevo certificado mTLS (nuevo serial)

Para otro participante, cambia `SSA_SOFTWARE_ID` (y claims relacionados) en `ssa.env` y vuelve a ejecutar el script. Ejemplo en el repo: `LIDER-BCI/`, `BANCO-ESTADO/`.

Tras regenerar JWKS, actualiza el SSA (`generate-test-ssa.sh`) y, si aplica, re-ejecuta el DCR.

---

## Seguridad

Archivos ignorados por git (ver [`../.gitignore`](../.gitignore)):

- `**/private.pem` — firma JWS
- `**/transport.key` — mTLS

Nunca commitear ni compartir claves privadas fuera del entorno local de desarrollo.
