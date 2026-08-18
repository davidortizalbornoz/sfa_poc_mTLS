import type { KeyObject } from "node:crypto";

export interface DpopPublicJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
}

export interface DpopKeyPair {
  privateKey: KeyObject;
  publicJwk: DpopPublicJwk;
  dpopJkt: string;
  privateKeyPem: string;
}

export interface CreateDpopProofOptions {
  privateKey: KeyObject;
  publicJwk: DpopPublicJwk;
  method: string;
  url: string;
  accessToken?: string;
  nonce?: string;
}

export interface MtlsClientConfig {
  clientId: string;
  clientName: string;
  scope: string;
  transportCert: string;
  transportKey: string;
  caCert: string;
  tokenEndpoint: string;
  citiesUrl: string;
  resolveAs: string;
  resolveApi: string;
}

export interface TokenResponse {
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
}
