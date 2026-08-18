import { createDpopKeyPair, createDpopProof } from "./dpop.js";
import { buildMtlsCurlCommand, runMtlsCurl } from "./mtls-curl.js";
import { loadMtlsClientConfig } from "./mtls-config.js";
import type { TokenResponse } from "./types.js";

async function fetchAccessToken(
  config: ReturnType<typeof loadMtlsClientConfig>,
): Promise<string> {
  const dpopKeys = createDpopKeyPair();
  const dpopProof = createDpopProof({
    privateKey: dpopKeys.privateKey,
    publicJwk: dpopKeys.publicJwk,
    method: "POST",
    url: config.tokenEndpoint,
  });

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: config.clientId,
    scope: config.scope,
  }).toString();

  const raw = runMtlsCurl({
    config,
    method: "POST",
    url: config.tokenEndpoint,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      DPoP: dpopProof,
    },
    body,
  });

  let tokens: TokenResponse;
  try {
    tokens = JSON.parse(raw) as TokenResponse;
  } catch {
    throw new Error(`Respuesta no JSON del AS: ${raw}`);
  }

  if (!tokens.access_token) {
    throw new Error(
      `Token falló: ${tokens.error ?? "unknown"} - ${tokens.error_description ?? raw}`,
    );
  }

  console.error(
    `Token obtenido (${config.clientId}, expires_in=${tokens.expires_in ?? "?"}s)`,
  );

  return tokens.access_token;
}

async function main(): Promise<void> {
  const config = loadMtlsClientConfig();
  const accessToken = await fetchAccessToken(config);

  const dpopKeys = createDpopKeyPair();
  const dpopProof = createDpopProof({
    privateKey: dpopKeys.privateKey,
    publicJwk: dpopKeys.publicJwk,
    method: "GET",
    url: config.citiesUrl,
    accessToken,
  });

  console.error("curl GET /cities (copiar a Postman; proof DPoP válido ~25 s):");
  console.log(
    buildMtlsCurlCommand({
      config,
      method: "GET",
      url: config.citiesUrl,
      resolve: config.resolveApi,
      headers: {
        Accept: "application/json",
        Authorization: `DPoP ${accessToken}`,
        DPoP: dpopProof,
      },
    }),
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error("");
  console.error(`Error: ${message}`);
  process.exit(1);
});
