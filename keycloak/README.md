# Keycloak — Authorization Server (vía gateway mTLS)

Entorno local de **Keycloak 26.2.5** con **PostgreSQL 16**, expuesto únicamente a través del **gateway Nginx** con mTLS obligatorio.

## Stack

| Contenedor | Servicio | Acceso host |
|---|---|---|
| `sfa-mTLS-postgres` | PostgreSQL | interno |
| `sfa-mTLS-keycloak` | Keycloak | interno (`:8080`) |
| `sfa-mTLS-resource-server` | API NestJS | interno (`:9090`) |
| `sfa-mTLS-gateway` | Nginx mTLS | **8443** (AS), **9443** (API) |

Añade a `/etc/hosts`:

```text
127.0.0.1 sfa.localtest.me api.localtest.me
```

## Preparación

```bash
cd clientRegistrationPolicy && ./scripts/generate-root-ca.sh
cd ../gateway && ./scripts/generate-gateway-certs.sh
docker compose up -d --build
```

Ver [`../gateway/README.md`](../gateway/README.md) para pruebas mTLS con `transport.crt`.

## Consola de administración

| Campo | Valor |
|---|---|
| URL | https://sfa.localtest.me:8443/admin/master/console/ |
| Usuario | `admin` |
| Password | `admin_local_dev` |

Requiere **certificado de cliente mTLS** en el navegador (Nginx rechaza con `400 No required SSL certificate was sent` si Chrome no lo presenta).

### macOS (Chrome / Safari)

```bash
cd clientRegistrationPolicy
./scripts/generate-transport-p12.sh          # usa SSA_SOFTWARE_ID de ssa.env
./scripts/import-transport-p12-macos.sh    # importa p12 + CA y habilita Chrome
```

Cierra Chrome por completo (`Cmd+Q`) y abre de nuevo la URL. El script usa un **llavero dedicado `sfa-mtls-poc`** (sin contraseña) para evitar el prompt del llavero Inicio de sesión al elegir el certificado.

## Realm `sfa-mtls-poc`

Import automático desde `keycloak/import/sfa-mtls-poc-realm.json`.

### Clientes OAuth relevantes

| Client ID | Auth | Uso |
|---|---|---|
| `LIDER-BCI`, `BANCO-ESTADO` | `client-x509` | TPP mTLS + `client_credentials` por certificado |
| `tpp-demo-m2m` | `client-secret` | M2M legacy (secret + DPoP) |
| `resource-server` | Bearer-only | Audience del API |

## Endpoints (gateway mTLS)

| Endpoint | URL |
|---|---|
| Discovery | https://sfa.localtest.me:8443/realms/sfa-mtls-poc/.well-known/openid-configuration |
| Token | https://sfa.localtest.me:8443/realms/sfa-mtls-poc/protocol/openid-connect/token |
| DCR | https://sfa.localtest.me:8443/realms/sfa-mtls-poc/clients-registrations/openid-connect |
| API health | https://api.localtest.me:9443/health |
| API cities | https://api.localtest.me:9443/cities |

Todas las URLs requieren presentar un certificado de cliente emitido por `clientRegistrationPolicy/registro_participantes/ca/root-ca.crt`.

## Keycloak + Nginx

- `KC_HOSTNAME=https://sfa.localtest.me:8443`
- `KC_PROXY=edge`, `KC_PROXY_HEADERS=xforwarded`
- `KC_SPI_X509CERT_LOOKUP_PROVIDER=nginx` — lee `ssl-client-cert` reenviado por Nginx

## Reimportar el realm

```bash
docker compose down -v
docker compose up -d
```
