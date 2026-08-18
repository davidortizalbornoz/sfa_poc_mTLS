import { UnauthorizedException } from '@nestjs/common';
import {
  createHash,
  createPublicKey,
  verify,
  type JsonWebKey,
} from 'node:crypto';

const ALLOWED_ALGORITHMS = new Set(['ES256', 'RS256', 'PS256']);
const MAX_PROOF_AGE_SECONDS = 300;
const MAX_CLOCK_SKEW_SECONDS = 60;

interface DpopProofHeader {
  typ?: string;
  alg?: string;
  jwk?: JsonWebKey;
}

interface DpopProofPayload {
  jti?: string;
  htm?: string;
  htu?: string;
  iat?: number;
  ath?: string;
  nonce?: string;
}

function decodeBase64Url(value: string): Buffer {
  const padded = value + '='.repeat((4 - (value.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function parseDpopProof(proof: string): {
  header: DpopProofHeader;
  payload: DpopProofPayload;
  signingInput: string;
  signature: Buffer;
} {
  const parts = proof.split('.');
  if (parts.length !== 3) {
    throw new UnauthorizedException('Invalid DPoP proof format');
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  try {
    const header = JSON.parse(
      decodeBase64Url(encodedHeader).toString('utf8'),
    ) as DpopProofHeader;
    const payload = JSON.parse(
      decodeBase64Url(encodedPayload).toString('utf8'),
    ) as DpopProofPayload;

    return {
      header,
      payload,
      signingInput: `${encodedHeader}.${encodedPayload}`,
      signature: decodeBase64Url(encodedSignature),
    };
  } catch {
    throw new UnauthorizedException('Invalid DPoP proof encoding');
  }
}

export function computeJwkThumbprint(jwk: JsonWebKey): string {
  let canonical: string;

  if (jwk.kty === 'EC') {
    canonical = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y,
    });
  } else if (jwk.kty === 'RSA') {
    canonical = JSON.stringify({
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n,
    });
  } else {
    throw new UnauthorizedException('Unsupported DPoP proof key type');
  }

  return createHash('sha256').update(canonical).digest('base64url');
}

function verifyProofSignature(
  header: DpopProofHeader,
  signingInput: string,
  signature: Buffer,
): void {
  if (header.typ !== 'dpop+jwt') {
    throw new UnauthorizedException('Invalid DPoP proof typ');
  }

  const alg = header.alg;
  if (!alg || !ALLOWED_ALGORITHMS.has(alg)) {
    throw new UnauthorizedException(
      `Unsupported DPoP proof algorithm: ${alg ?? 'missing'}`,
    );
  }

  if (!header.jwk) {
    throw new UnauthorizedException('DPoP proof missing jwk header');
  }

  const publicKey = createPublicKey({ key: header.jwk, format: 'jwk' });
  const verified =
    alg === 'ES256'
      ? verify(
          'sha256',
          Buffer.from(signingInput),
          { key: publicKey, dsaEncoding: 'ieee-p1363' },
          signature,
        )
      : verify('sha256', Buffer.from(signingInput), publicKey, signature);

  if (!verified) {
    throw new UnauthorizedException('Invalid DPoP proof signature');
  }
}

function normalizeHtu(value: string): string {
  const url = new URL(value);
  url.search = '';
  url.hash = '';
  return url.toString();
}

export function buildRequestTargetUri(request: {
  protocol: string;
  originalUrl: string;
  get(name: string): string | undefined;
}): string {
  const host = request.get('host');
  if (!host) {
    throw new UnauthorizedException(
      'Cannot determine request host for DPoP validation',
    );
  }

  const path = request.originalUrl.split('?')[0].split('#')[0];
  return normalizeHtu(`${request.protocol}://${host}${path}`);
}

export function validateDpopProof(options: {
  proof: string;
  method: string;
  url: string;
  accessToken: string;
  expectedJkt: string;
}): void {
  const { header, payload, signingInput, signature } = parseDpopProof(
    options.proof,
  );

  verifyProofSignature(header, signingInput, signature);

  const proofJkt = computeJwkThumbprint(header.jwk!);
  if (proofJkt !== options.expectedJkt) {
    throw new UnauthorizedException(
      'DPoP proof key does not match token cnf.jkt',
    );
  }

  if (payload.htm?.toUpperCase() !== options.method.toUpperCase()) {
    throw new UnauthorizedException('DPoP proof htm mismatch');
  }

  if (normalizeHtu(payload.htu ?? '') !== normalizeHtu(options.url)) {
    throw new UnauthorizedException('DPoP proof htu mismatch');
  }

  if (typeof payload.iat !== 'number') {
    throw new UnauthorizedException('DPoP proof missing iat');
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.iat > now + MAX_CLOCK_SKEW_SECONDS) {
    throw new UnauthorizedException('DPoP proof iat is in the future');
  }

  if (now - payload.iat > MAX_PROOF_AGE_SECONDS) {
    throw new UnauthorizedException('DPoP proof expired');
  }

  if (!payload.jti) {
    throw new UnauthorizedException('DPoP proof missing jti');
  }

  const expectedAth = createHash('sha256')
    .update(options.accessToken)
    .digest('base64url');

  if (payload.ath !== expectedAth) {
    throw new UnauthorizedException('DPoP proof ath mismatch');
  }
}
