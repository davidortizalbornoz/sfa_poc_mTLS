import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadOptionalDotEnv, loadSsaEnv } from "./load-ssa-env.js";
import type { MtlsClientConfig } from "./types.js";

const TPP_CLIENT_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = join(TPP_CLIENT_ROOT, "..");

loadOptionalDotEnv(TPP_CLIENT_ROOT);

function requiredPath(path: string, label: string): string {
  if (!existsSync(path)) {
    throw new Error(`No existe ${label}: ${path}`);
  }
  return path;
}

export function loadMtlsClientConfig(): MtlsClientConfig {
  const ssaEnvPath = resolve(
    process.env.SSA_ENV ?? join(REPO_ROOT, "clientRegistrationPolicy/ssa.env"),
  );
  const ssa = loadSsaEnv(ssaEnvPath);

  const clientId = process.env.SSA_SOFTWARE_ID ?? ssa.SSA_SOFTWARE_ID;
  if (!clientId) {
    throw new Error(`SSA_SOFTWARE_ID requerido en ${ssaEnvPath}`);
  }

  const clientJwksDir = join(REPO_ROOT, "clientRegistrationPolicy/client-jwks", clientId);
  const caDir = join(REPO_ROOT, "clientRegistrationPolicy/registro_participantes/ca");

  const keycloakHost = (
    process.env.KEYCLOAK_HOST ?? "https://sfa.localtest.me:8443"
  ).replace(/\/$/, "");
  const apiHost = (process.env.API_HOST ?? "https://api.localtest.me:9443").replace(
    /\/$/,
    "",
  );
  const realm = process.env.KEYCLOAK_REALM ?? "sfa-mtls-poc";
  const resolveIp = process.env.MTLS_RESOLVE_HOST ?? "127.0.0.1";

  const asHost = new URL(keycloakHost).host;
  const apiHostName = new URL(apiHost).host;

  return {
    clientId,
    clientName: ssa.SSA_SOFTWARE_CLIENT_NAME ?? clientId,
    scope: process.env.MTLS_SCOPE ?? "accounts:read",
    transportCert: requiredPath(
      join(clientJwksDir, "transport.crt"),
      "transport.crt",
    ),
    transportKey: requiredPath(
      join(clientJwksDir, "transport.key"),
      "transport.key",
    ),
    caCert: requiredPath(join(caDir, "root-ca.crt"), "root-ca.crt"),
    tokenEndpoint: `${keycloakHost}/realms/${realm}/protocol/openid-connect/token`,
    citiesUrl: `${apiHost}/cities`,
    resolveAs: `${asHost}:${resolveIp}`,
    resolveApi: `${apiHostName}:${resolveIp}`,
  };
}
