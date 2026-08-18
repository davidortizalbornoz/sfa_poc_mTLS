# Resource Server — NestJS + DPoP

API protegida con **JWT DPoP-bound de Keycloak**. Expone datos de ciudades de Chile y valida tokens emitidos por el realm `sfa-poc`.

Requiere en cada request protegido:

- `Authorization: DPoP <access_token>`
- Header `DPoP: <proof JWT>` con claim `ath` y clave pública que coincida con `cnf.jkt` del token

## Requisitos

- **Node.js 20+** (ver `.nvmrc`)
- **Keycloak en ejecución** ([keycloak/README.md](../keycloak/README.md))
- Puerto **9090** libre

## Configuración

```bash
cd resource_server
cp .env.example .env   # si aún no existe
nvm use
npm install            # solo la primera vez
```

Variables (`.env`):

| Variable | Valor | Descripción |
|---|---|---|
| `PORT` | `9090` | Puerto HTTP del API |
| `KEYCLOAK_ISSUER` | `http://sfa.localtest.me:8080/realms/sfa-poc` | Emisor del JWT (debe coincidir exactamente con `iss` del token) |
| `KEYCLOAK_JWKS_URI` | `http://sfa.localtest.me:8080/.../certs` | Claves públicas JWKS |
| `KEYCLOAK_AUDIENCE` | `resource-server` | Audience esperada en el token |
| `REQUIRED_SCOPE` | `accounts:read` | Scope obligatorio |

## Ejecución

```bash
nvm use
npm run start:dev
```

Producción local:

```bash
npm run build
npm run start:prod
```

Salida esperada:

```text
Resource Server listening on http://localhost:9090
```

## Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| `GET` | `/health` | No | Health check del servicio |
| `GET` | `/cities` | DPoP JWT | Listado de ciudades de Chile |

### `GET /health`

```bash
curl -s http://localhost:9090/health | python3 -m json.tool
```

### `GET /cities`

Requiere:

- `Authorization: DPoP <access_token>` (no Bearer)
- Header `DPoP: <proof>` firmado con la misma clave usada en el flujo OAuth
- Issuer: `http://sfa.localtest.me:8080/realms/sfa-poc`
- Audience: `resource-server`
- Scope: `accounts:read`
- Claim `cnf.jkt` en el JWT igual al thumbprint de la clave del proof

```bash
curl -s http://localhost:9090/cities \
  -H "Authorization: DPoP <ACCESS_TOKEN>" \
  -H "DPoP: <DPOP_PROOF>" | python3 -m json.tool
```

Sin token o sin proof DPoP → **401 Unauthorized**. Bearer ya no es aceptado.

## Obtener un access token DPoP-bound

Usa el cliente TPP (genera claves DPoP y solicita scope `accounts:read`):

```bash
cd ../tpp-client
nvm use
npm start
```

Para probar el flujo completo TPP → Resource Server, define en `tpp-client/.env`:

```env
RESOURCE_SERVER_URL=http://localhost:9090/cities
```

El TPP client llamará `/cities` automáticamente con `Authorization: DPoP` y header `DPoP`.

## Respuesta de `/cities`

Arreglo JSON con **12 ciudades** de Chile. Cada objeto incluye:

| Campo | Descripción |
|---|---|
| `id` | Identificador slug |
| `name` | Nombre de la ciudad |
| `region` | Región administrativa |
| `province` | Provincia |
| `population` | Población estimada |
| `foundedYear` | Año de fundación |
| `areaKm2` | Superficie en km² |
| `coordinates` | Latitud y longitud |
| `climate` | Clima predominante |
| `economicActivity` | Actividad económica principal |
| `highlights` | Rasgos sobresalientes |
| `notableFacts` | Datos relevantes |
| `unescoSite` | Si tiene patrimonio UNESCO en su entorno |

Ciudades incluidas: Santiago, Valparaíso, Viña del Mar, Concepción, La Serena, Antofagasta, Iquique, Temuco, Puerto Montt, Punta Arenas, Arica y Castro.

## Estructura

```text
resource_server/
├── .env
├── .env.example
├── .nvmrc
├── src/
│   ├── auth/           # JWT strategy (JWKS) + validacion DPoP
│   ├── cities/         # GET /cities
│   ├── health/         # GET /health
│   ├── app.module.ts
│   └── main.ts
└── test/
```

## Tests

```bash
npm run test:e2e
```

## Puertos del POC

| Servicio | Puerto |
|---|---|
| Keycloak HTTP | 8080 |
| Keycloak health | 9000 |
| TPP callback | 3000 |
| **Resource Server** | **9090** |

## Validacion DPoP

El Resource Server verifica:

1. JWT firmado por Keycloak (JWKS, `iss`, `aud`, `exp`, scope)
2. Token DPoP-bound (`cnf.jkt` presente)
3. Proof DPoP (`typ: dpop+jwt`, firma ES256/RS256)
4. `htm` y `htu` coinciden con la request
5. `ath` = SHA-256 base64url del access token
6. Thumbprint de la clave del proof = `cnf.jkt`

## Solución de problemas

### `401 Unauthorized` con token válido

- Usa `Authorization: DPoP`, no `Bearer`.
- Incluye header `DPoP` con proof nuevo por request (incluye `ath`).
- Verifica que el token incluya scope `accounts:read` (ejecuta TPP client con el scope configurado).
- Confirma que la audience del JWT sea `resource-server`.
- Revisa que `KEYCLOAK_ISSUER` coincida exactamente con el claim `iss` del token.
- El `htu` del proof debe coincidir con la URL exacta (ej. `http://localhost:9090/cities`).

### Keycloak no responde / error JWKS

```bash
curl -s http://localhost:8080/realms/sfa-poc/protocol/openid-connect/certs
```

### Puerto 9090 ocupado

Cambia `PORT` en `.env` (ej. `9091`).
