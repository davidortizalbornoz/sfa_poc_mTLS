# Keycloak — Authorization Server

Entorno local de **Keycloak 26.2.5** con **PostgreSQL 16**, pensado para desarrollo en **localhost** con Docker Desktop.

## Qué incluye

- **Keycloak** como Authorization Server (OAuth 2.0 / OpenID Connect)
- **PostgreSQL** persistente (los datos sobreviven reinicios)
- Import automático del realm **`sfa-poc`** al arrancar
- Features habilitadas: **PAR** y **DPoP** (preparación FAPI)


| Contenedor | Servicio | Puertos |
|---|---|---|
| `sfa-postgres` | PostgreSQL | 5432 (interno) |
| `sfa-keycloak` | Keycloak | 8080, 9000 |


Respuesta esperada: `"status": "UP"`.

### Consola de administración

| Campo | Valor |
|---|---|
| URL | http://sfa.localtest.me:8080/admin |
| Usuario | `admin` |
| Password | `admin_local_dev` |

### OpenID Discovery (realm importado)

```bash
curl -s http://sfa.localtest.me:8080/realms/sfa-poc/.well-known/openid-configuration | python3 -m json.tool
```

## Realm `sfa-poc` (import automático)

El archivo `keycloak/import/sfa-mTLS-poc-realm.json` se importa al iniciar Keycloak (`start-dev --import-realm`).

### Clientes OAuth

| Client ID | Tipo | Uso |
|---|---|---|
| `tpp-demo` | Confidential | Cliente principal del POC (PAR + PKCE + DPoP) |
| `tpp-demo-public` | Public | Authorization Code con PKCE sin secret |
| `tpp-demo-mtls` | X509 | Preparado para `tls_client_auth` |
| `tpp-demo-m2m` | Confidential + Service Account | `client_credentials` + DPoP (M2M, sin usuario) |
| `resource-server` | Bearer-only | Audience lógica del API protegido |

**Secret de `tpp-demo`:** `tpp-demo-secret-local-dev`

**Secret de `tpp-demo-m2m`:** `tpp-demo-m2m-secret-local-dev`


### Usuarios de prueba

| Usuario | Password | Roles principales |
|---|---|---|
| `demo-user` | `demo-user-local-dev` | account-viewer, tpp-operator |
| `admin-poc` | `admin-poc-local-dev` | account-admin, account-viewer, tpp-operator |

### Scopes personalizados

- `accounts:read`
- `accounts:write`
- `payments:read`

## Endpoints útiles

| Endpoint | URL |
|---|---|
| Landing | http://sfa.localtest.me:8080 |
| Admin Console | http://sfa.localtest.me:8080/admin |
| Discovery | http://sfa.localtest.me:8080/realms/sfa-poc/.well-known/openid-configuration |
| Authorization | http://sfa.localtest.me:8080/realms/sfa-poc/protocol/openid-connect/auth |
| Token | http://sfa.localtest.me:8080/realms/sfa-poc/protocol/openid-connect/token |
| PAR | http://sfa.localtest.me:8080/realms/sfa-poc/protocol/openid-connect/ext/par/request |
| JWKS | http://sfa.localtest.me:8080/realms/sfa-poc/protocol/openid-connect/certs |

## Comandos habituales

```bash
# Parar servicios (conserva datos)
docker compose down

# Parar y borrar volúmenes (reset total de BD y realms importados)
docker compose down -v

# Reiniciar solo Keycloak
docker compose restart keycloak

# Logs en tiempo real
docker compose logs -f keycloak
```

## Reimportar el realm

Keycloak usa estrategia **`IGNORE_EXISTING`**: si el realm ya existe, **no sobrescribe** cambios del JSON.


```bash
docker compose down -v
docker compose up -d
```
Para bci-idp remoto, borra el realm desde http://10.67.245.106:5050/admin y reinicia el contenedor, o recrea el volumen en ese host.




