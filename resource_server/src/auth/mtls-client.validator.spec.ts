import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { UnauthorizedException } from '@nestjs/common';
import {
  computeCertThumbprintS256,
  decodeNginxClientCertHeader,
  extractCommonName,
  parseClientCertificate,
  validateMtlsClientCert,
} from './mtls-client.validator';

const REPO_ROOT = join(__dirname, '../../..');
const JWKS_DIR = join(REPO_ROOT, 'clientRegistrationPolicy/client-jwks');

function loadPem(clientId: string): string {
  return readFileSync(join(JWKS_DIR, clientId, 'transport.crt'), 'utf8');
}

function nginxCertHeader(pem: string): string {
  return encodeURIComponent(pem.trim());
}

describe('mtls-client.validator', () => {
  const bancoPem = loadPem('BANCO-ESTADO');
  const matchPem = loadPem('MATCH-BCI');
  const bancoCert = parseClientCertificate(nginxCertHeader(bancoPem));
  const bancoThumbprint = computeCertThumbprintS256(bancoCert);

  it('decodes nginx url-encoded client cert header', () => {
    const decoded = decodeNginxClientCertHeader(nginxCertHeader(bancoPem));
    expect(decoded).toContain('BEGIN CERTIFICATE');
    expect(extractCommonName(parseClientCertificate(decoded).subject)).toBe(
      'BANCO-ESTADO',
    );
  });

  it('accepts matching CN and x5t#S256', () => {
    expect(() =>
      validateMtlsClientCert({
        headers: {
          'ssl-client-verify': 'SUCCESS',
          'ssl-client-cert': nginxCertHeader(bancoPem),
        },
        azp: 'BANCO-ESTADO',
        expectedCertThumbprint: bancoThumbprint,
        required: true,
      }),
    ).not.toThrow();
  });

  it('rejects certificate CN mismatch with azp', () => {
    expect(() =>
      validateMtlsClientCert({
        headers: {
          'ssl-client-verify': 'SUCCESS',
          'ssl-client-cert': nginxCertHeader(matchPem),
        },
        azp: 'BANCO-ESTADO',
        expectedCertThumbprint: bancoThumbprint,
        required: true,
      }),
    ).toThrow(UnauthorizedException);
  });

  it('rejects certificate thumbprint mismatch with token cnf.x5t#S256', () => {
    const matchCert = parseClientCertificate(nginxCertHeader(matchPem));
    const matchThumbprint = computeCertThumbprintS256(matchCert);

    expect(matchThumbprint).not.toBe(bancoThumbprint);
    expect(() =>
      validateMtlsClientCert({
        headers: {
          'ssl-client-verify': 'SUCCESS',
          'ssl-client-cert': nginxCertHeader(matchPem),
        },
        azp: 'MATCH-BCI',
        expectedCertThumbprint: bancoThumbprint,
        required: true,
      }),
    ).toThrow('mTLS client certificate does not match token cnf.x5t#S256');
  });

  it('requires client cert when configured', () => {
    expect(() =>
      validateMtlsClientCert({
        headers: {},
        azp: 'BANCO-ESTADO',
        required: true,
      }),
    ).toThrow('Missing mTLS client certificate');
  });
});
