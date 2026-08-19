# TPP Client — mTLS + DPoP

Cliente de demostración para el POC **tls_client_auth** vía gateway Nginx.

Lee el participante activo desde `clientRegistrationPolicy/ssa.env` (`SSA_SOFTWARE_ID`) y usa sus certificados en `client-jwks/<id>/`.

## Requisitos

- Node.js 20+ (`nvm use`)
- Stack Docker levantado (`docker compose up -d`)
- `/etc/hosts`: `127.0.0.1 sfa.localtest.me api.localtest.me`
- Cliente registrado en Keycloak (DCR) con `tls_client_auth` para el `SSA_SOFTWARE_ID` configurado

> Si el script responde `invalid_client`, registra el participante vía DCR (`clientRegistrationPolicy/pauta_ejecucion_DCR_SSA.txt`).

## Instalación

```bash
cd tpp-client
npm install
```

## Comando

```bash
npm run fintech-mtls-dpop-cities
```

1. **Obtiene el token** en Keycloak (`POST /token` con mTLS + DPoP, sin `client_assertion`).
2. **Imprime el curl** de `POST /token` usado (referencia; el proof ya fue consumido).
3. **Imprime el curl** de `GET /cities` listo para copiar en Postman (no llama al resource server).

El curl incluye:

- `--cert` / `--key` → `transport.crt` / `transport.key`
- `--cacert` → CA raíz del POC
- `--resolve api.localtest.me:9443:127.0.0.1`
- `Authorization: DPoP <access_token>`
- Header `DPoP` con proof para `GET /cities`

> El proof DPoP del curl expira en ~25 s. Cópialo y envíalo en Postman de inmediato, o usa `postman/pre-request-cities.js` con el `access_token` del log si necesitas regenerarlo.

## Postman

1. **Certificado cliente:** Settings → Certificates → `api.localtest.me:9443` con `transport.crt` + `transport.key`.
2. Ejecuta `npm run fintech-mtls-dpop-cities` y copia el curl (o importa URL/headers manualmente).
3. Opcional: Pre-request Script `postman/pre-request-cities.js` + variable `access_token` para regenerar DPoP al enviar.

## Configuración

| Origen | Variable | Default |
|---|---|---|
| `ssa.env` | `SSA_SOFTWARE_ID` | participante y rutas de certificados |
| `ssa.env` | `SSA_SOFTWARE_CLIENT_NAME` | nombre en logs |
| `.env` (opcional) | `SSA_ENV` | `../clientRegistrationPolicy/ssa.env` |
| `.env` | `KEYCLOAK_HOST` | `https://sfa.localtest.me:8443` |
| `.env` | `API_HOST` | `https://api.localtest.me:9443` |
| `.env` | `KEYCLOAK_REALM` | `sfa-mtls-poc` |
| `.env` | `MTLS_SCOPE` | `accounts:read` |

## Flujo

```bash
# 1. Ajustar participante en ssa.env (ej. MATCH-BCI)
# 2. Token + curl cities para Postman
npm run fintech-mtls-dpop-cities
```
