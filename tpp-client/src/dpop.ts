import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  type JsonWebKey,
} from "node:crypto";
import type {
  CreateDpopProofOptions,
  DpopKeyPair,
  DpopPublicJwk,
} from "./types.js";

function base64UrlEncode(value: Buffer | string): string {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function toPublicJwk(jwk: JsonWebKey): DpopPublicJwk {
  if (jwk.kty !== "EC" || !jwk.crv || !jwk.x || !jwk.y) {
    throw new Error("Clave DPoP invalida: se esperaba EC P-256");
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
  };
}

export function computeJwkThumbprint(jwk: DpopPublicJwk): string {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });

  return createHash("sha256").update(canonical).digest("base64url");
}

export function createDpopKeyPair(): DpopKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  const publicJwk = toPublicJwk(publicKey.export({ format: "jwk" }));
  const privateKeyPem = privateKey.export({
    format: "pem",
    type: "pkcs8",
  }) as string;

  return {
    privateKey,
    publicJwk,
    dpopJkt: computeJwkThumbprint(publicJwk),
    privateKeyPem,
  };
}

export function loadDpopKeyPairFromPem(privateKeyPem: string): DpopKeyPair {
  const privateKey = createPrivateKey(privateKeyPem);
  const publicJwk = toPublicJwk(privateKey.export({ format: "jwk" }) as JsonWebKey);

  return {
    privateKey,
    publicJwk,
    dpopJkt: computeJwkThumbprint(publicJwk),
    privateKeyPem,
  };
}

export function createDpopProof({
  privateKey,
  publicJwk,
  method,
  url,
  accessToken,
  nonce,
}: CreateDpopProofOptions): string {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: publicJwk,
  };

  const target = new URL(url);
  target.search = "";
  target.hash = "";

  const payload: Record<string, string | number> = {
    jti: base64UrlEncode(randomBytes(16)),
    htm: method.toUpperCase(),
    htu: target.toString(),
    iat: Math.floor(Date.now() / 1000),
  };

  if (accessToken) {
    payload.ath = createHash("sha256")
      .update(accessToken)
      .digest("base64url");
  }

  if (nonce) {
    payload.nonce = nonce;
  }

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = sign("sha256", Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  }).toString("base64url");

  return `${signingInput}.${signature}`;
}
