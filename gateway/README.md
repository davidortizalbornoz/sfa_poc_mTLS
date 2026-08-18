# Gateway Nginx — mTLS para Keycloak y Resource Server

Termina TLS con **certificado de cliente obligatorio** (`verify_client on`) usando la CA del POC (`clientRegistrationPolicy/registro_participantes/ca/root-ca.crt`).

## Hostnames (añadir a `/etc/hosts`)

```text
127.0.0.1 sfa.localtest.me api.localtest.me
```

## Puertos

| Host | Puerto | Upstream | Uso |
|---|---|---|---|
| `sfa.localtest.me` | **8443** | Keycloak `:8080` | Authorization Server (todo el tráfico OIDC/admin) |
| `api.localtest.me` | **9443** | Resource Server `:9090` | API protegida (`/cities`, `/health`) |

Keycloak y Resource Server **no** exponen puertos al host; solo el gateway.

## Preparación (una vez por entorno)

```bash
# CA raíz + certs TPP (si aún no existen)
cd clientRegistrationPolicy
./scripts/generate-root-ca.sh
./scripts/generate-client-jwks.sh

# Certificados TLS del gateway (servidor)
cd ../gateway
chmod +x scripts/generate-gateway-certs.sh
./scripts/generate-gateway-certs.sh
```

Genera en `gateway/certs/`:

- `sfa.localtest.me.crt` / `.key` — TLS servidor Keycloak
- `api.localtest.me.crt` / `.key` — TLS servidor API
- `root-ca.crt` — copia para referencia

## Levantar stack

```bash
docker compose up -d --build
```

## Probar mTLS

### Health API (sin JWT, pero con certificado cliente)

```bash
curl --cert ../clientRegistrationPolicy/client-jwks/LIDER-BCI/transport.crt \
     --key ../clientRegistrationPolicy/client-jwks/LIDER-BCI/transport.key \
     --cacert ../clientRegistrationPolicy/registro_participantes/ca/root-ca.crt \
     https://api.localtest.me:9443/health
```

### Token client_credentials (certificado X509 + DPoP, sin client_assertion)

Keycloak exige header `DPoP` cuando el cliente tiene `dpop.bound.access.tokens=true`.
El Subject DN del certificado debe coincidir con `x509.subjectdn` en formato RFC2253 (`C=CL,O=<org>,CN=<id>`); el SPI DCR lo normaliza automáticamente.

```bash
curl --cert ../clientRegistrationPolicy/client-jwks/MATCH-BCI/transport.crt \
     --key ../clientRegistrationPolicy/client-jwks/MATCH-BCI/transport.key \
     --cacert ../clientRegistrationPolicy/registro_participantes/ca/root-ca.crt \
     --resolve sfa.localtest.me:8443:127.0.0.1 \
     https://sfa.localtest.me:8443/realms/sfa-mtls-poc/protocol/openid-connect/token \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -H "DPoP: <proof-jwt>" \
     -d 'grant_type=client_credentials&client_id=MATCH-BCI&scope=accounts:read'
```

### DCR (registro anónimo — el gateway exige mTLS; usa un cert válido del POC)

```bash
SSA=$(../clientRegistrationPolicy/scripts/generate-test-ssa.sh)
curl --cert ../clientRegistrationPolicy/client-jwks/MATCH-BCI/transport.crt \
     --key ../clientRegistrationPolicy/client-jwks/MATCH-BCI/transport.key \
     --cacert ../clientRegistrationPolicy/registro_participantes/ca/root-ca.crt \
     https://sfa.localtest.me:8443/realms/sfa-mtls-poc/clients-registrations/openid-connect \
     -H 'Content-Type: application/json' \
     -H "X-Software-Statement: $SSA" \
     -d '{ ... }'
```

## Keycloak

Variables relevantes en `docker-compose.yml`:

- `KC_PROXY=edge` + `KC_PROXY_HEADERS=xforwarded`
- `KC_HOSTNAME=https://sfa.localtest.me:8443`
- `KC_SPI_X509CERT_LOOKUP_PROVIDER=nginx`

Nginx reenvía `ssl-client-cert` para que el authenticator `client-x509` valide el Subject DN del TPP.

## Notas

- **Todo** el tráfico a Keycloak y al API requiere certificado de cliente emitido por la CA del POC.
- Consola admin en navegador (macOS):

```bash
cd clientRegistrationPolicy
./scripts/generate-transport-p12.sh
./scripts/import-transport-p12-macos.sh
# Cierra Chrome (Cmd+Q) y abre https://sfa.localtest.me:8443/admin/master/console/
```

> Si ves `400 Bad Request — No required SSL certificate was sent`, Chrome no presentó el cert en TLS (`verify=NONE`). Reimporta con `import-transport-p12-macos.sh` (usa `-A` para permitir acceso a la clave privada).
- El Resource Server sigue validando JWT DPoP-bound en `/cities`; mTLS es capa de transporte adicional.
