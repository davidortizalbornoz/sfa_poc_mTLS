# registro_participantes/ — Directorio de participantes y CA raíz

Material criptográfico que simula el **Directorio de participantes** del ecosistema de Finanzas Abiertas (CMF Chile) y la **CA raíz** del POC para certificados mTLS.

En producción, el Directorio emite **Software Statements (SSA)** firmados y publica su **JWKS**. La CA raíz real del ecosistema es distinta; aquí se emula una CA local solo para desarrollo.

Las claves de los TPP viven en [`../client-jwks/`](../client-jwks/). Documentación general: [`../README.md`](../README.md).

---

## Vista general

```
registro_participantes/
├── directory-private.pem       ← SECRETO: firma SSA (Directorio)
├── directory-public.pem        ← clave pública del Directorio
├── directory-jwks.json         ← JWKS público del Directorio
├── sample-software-statement.jwt ← SSA de ejemplo (generate-test-ssa.sh)
└── ca/
    ├── root-ca.crt             ← certificado CA raíz (truststore)
    ├── root-ca.key             ← SECRETO: emite transport.crt de TPPs
    └── root-ca.srl             ← serial OpenSSL (interno)
```

---

## Directorio — firma del Software Statement (DCR)

Simula la entidad que **autoriza** el software TPP antes del registro dinámico en el Authorization Server.

| Archivo | Formato | ¿Quién lo usa? | Para qué sirve |
|---|---|---|---|
| **`directory-private.pem`** | RSA PKCS#8 (PEM) | Script `generate-test-ssa.sh` | **Firmar** el JWT del Software Statement (`PS256`). Equivalente a la clave privada del Directorio en QA/producción. **No exponer.** |
| **`directory-public.pem`** | RSA SPKI (PEM) | Keycloak (opcional) | Clave pública en PEM. Respaldo si el AS no puede cargar JWKS por URI (`directory-public-key-pem`). |
| **`directory-jwks.json`** | JWKS (JSON) | Authorization Server (Keycloak) | Conjunto público con `kid: sfa-poc-directory-1`, `alg: PS256`. El AS **verifica** la firma del SSA contra estas claves. Montado en el POC como `file:/opt/keycloak/data/test-directory-jwks.json`. |
| **`sample-software-statement.jwt`** | JWT compacto (JWS) | TPP en POST DCR | SSA de ejemplo listo para pruebas. Regenerar con `./scripts/generate-test-ssa.sh` tras cambiar `ssa.env`. |

### Flujo DCR con el SSA

1. El TPP obtiene un SSA firmado por el Directorio (en el POC: `generate-test-ssa.sh`).
2. El TPP envía el SSA en el registro dinámico (`software_statement` en el body).
3. Keycloak valida la firma JWS usando `directory-jwks.json`.
4. Si es válido, aplica claims (`software_id`, `software_jwks_uri`, `redirect_uris`, …) al cliente OAuth.

El SSA **no** es un certificado TLS ni sustituye las claves del TPP en `client-jwks/`.

---

## CA raíz — certificados mTLS de transporte

Autoridad certificadora **local del POC** que emite certificados X.509 de cliente para TPPs. Generada con `./scripts/generate-root-ca.sh`.

| Archivo | Formato | ¿Quién lo usa? | Para qué sirve |
|---|---|---|---|
| **`ca/root-ca.crt`** | X.509 self-signed (PEM) | Authorization Server, API Gateway, curl `--cacert` | **Truststore**: confiar en certificados `transport.crt` emitidos por esta CA. Subject default: `CN=SFA POC Root CA`. |
| **`ca/root-ca.key`** | RSA (PEM) | Solo `generate-client-jwks.sh` | Clave privada de la CA. **Firma** los certificados `transport.crt` de cada TPP. **No versionar ni exponer.** |
| **`ca/root-ca.srl`** | Texto (número serial) | OpenSSL | Archivo de control de seriales al emitir certificados. Regenerado automáticamente. |

### Relación con certificados de TPP

```
root-ca.key  ──firma──►  client-jwks/{SOFTWARE_ID}/transport.crt
root-ca.crt  ──confía──►  Authorization Server (valida transport.crt presentado por el TPP)
```

La CA raíz **no** interviene en firmas JWT ni en el SSA. Solo certifica identidades de transporte TLS.

### Regenerar la CA

```bash
FORCE=1 ./scripts/generate-root-ca.sh
```

**Advertencia:** invalida todos los `transport.crt` existentes en `client-jwks/`. Debes re-ejecutar `generate-client-jwks.sh` para cada TPP.

---

## Scripts que escriben aquí

| Script | Archivos que genera o actualiza |
|---|---|
| `generate-root-ca.sh` | `ca/root-ca.crt`, `ca/root-ca.key`, `ca/root-ca.srl` |
| `generate-test-ssa.sh` | `sample-software-statement.jwt` |
| `generate-client-jwks.sh` | No escribe aquí; **lee** `ca/root-ca.*` para firmar certificados en `client-jwks/` |

---

## Variables relevantes (`ssa.env`)

### SSA (Directorio)

| Variable | Claim / uso |
|---|---|
| `SSA_ISSUER` | `iss` del SSA |
| `SSA_SOFTWARE_ID` | `software_id` |
| `SSA_ORGANISATION_ID` | `organisation_id` |
| `SSA_SOFTWARE_JWKS_URI` | `software_jwks_uri` |
| `SSA_SOFTWARE_CLIENT_NAME` | `software_client_name` |
| `SSA_REDIRECT_URIS` | `redirect_uris` |
| `SSA_SOFTWARE_VERSION` | `software_version` |
| `SSA_JWT_KID` | `kid` del header; debe coincidir con `directory-jwks.json` |

### CA raíz

| Variable | Default | Uso |
|---|---|---|
| `CA_SUBJECT` | `/CN=SFA POC Root CA/O=Finanzas Abiertas POC/C=CL` | DN del certificado raíz |
| `CA_VALIDITY_DAYS` | `3650` | Vigencia del certificado CA |
| `CA_KEY_BITS` | `4096` | Tamaño clave RSA de la CA |

Ver plantilla completa: [`../ssa.env.example`](../ssa.env.example).

---

## Regenerar artefactos

Desde `clientRegistrationPolicy/`:

```bash
# 1. CA raíz (una vez por entorno)
./scripts/generate-root-ca.sh

# 2. Material del TPP (JWS + mTLS) — ver client-jwks/README.md
./scripts/generate-client-jwks.sh

# 3. SSA firmado por el Directorio
./scripts/generate-test-ssa.sh
```

Si no existe `ssa.env`, los scripts usan `ssa.env.example`.

---

## Relación con Keycloak

En el realm `sfa-poc`, la Client Registration Policy **SFA Software Statement**:

- Carga `directory-jwks.json` vía `directory-jwks-uri`
- Verifica la firma PS256 del SSA
- Aplica los claims al cliente OAuth registrado dinámicamente

Para mTLS, configura el truststore del AS con `ca/root-ca.crt`.
