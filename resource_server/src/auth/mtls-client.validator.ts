import { UnauthorizedException } from '@nestjs/common';
import { X509Certificate, createHash } from 'node:crypto';

export interface MtlsClientValidationOptions {
  headers: Record<string, string | string[] | undefined>;
  azp: string;
  expectedCertThumbprint?: string;
  required: boolean;
}

function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const value = headers[name];
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

export function decodeNginxClientCertHeader(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    return '';
  }

  if (trimmed.includes('%')) {
    return decodeURIComponent(trimmed);
  }

  if (trimmed.includes('\\n')) {
    return trimmed.replace(/\\n/g, '\n');
  }

  return trimmed;
}

export function computeCertThumbprintS256(cert: X509Certificate): string {
  return createHash('sha256').update(cert.raw).digest('base64url');
}

export function extractCommonName(subject: string): string | undefined {
  for (const line of subject.split('\n')) {
    const match = line.trim().match(/^CN=(.+)$/);
    if (match) {
      return match[1];
    }
  }

  const inlineMatch = subject.match(/(?:^|,\s*)CN=([^,]+)/);
  return inlineMatch?.[1]?.trim();
}

export function parseClientCertificate(
  certHeader: string,
): X509Certificate {
  const pem = decodeNginxClientCertHeader(certHeader);
  if (!pem.includes('BEGIN CERTIFICATE')) {
    throw new UnauthorizedException('Invalid mTLS client certificate encoding');
  }

  try {
    return new X509Certificate(pem);
  } catch {
    throw new UnauthorizedException('Invalid mTLS client certificate');
  }
}

export function validateMtlsClientCert(
  options: MtlsClientValidationOptions,
): void {
  const certHeader = getHeader(options.headers, 'ssl-client-cert');
  const verify = getHeader(options.headers, 'ssl-client-verify');

  if (!certHeader) {
    if (options.required) {
      throw new UnauthorizedException('Missing mTLS client certificate');
    }
    return;
  }

  if (verify && verify !== 'SUCCESS') {
    throw new UnauthorizedException(
      `Invalid mTLS client verification: ${verify}`,
    );
  }

  const cert = parseClientCertificate(certHeader);
  const commonName = extractCommonName(cert.subject);

  if (!commonName || commonName !== options.azp) {
    throw new UnauthorizedException(
      'mTLS client certificate CN does not match token client (azp)',
    );
  }

  if (options.expectedCertThumbprint) {
    const actualThumbprint = computeCertThumbprintS256(cert);
    if (actualThumbprint !== options.expectedCertThumbprint) {
      throw new UnauthorizedException(
        'mTLS client certificate does not match token cnf.x5t#S256',
      );
    }
  }
}
