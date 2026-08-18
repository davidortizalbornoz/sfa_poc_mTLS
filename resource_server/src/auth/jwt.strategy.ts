import {
  Injectable,
  Logger,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { createPublicKey, type JsonWebKey } from 'node:crypto';
import type { Request } from 'express';
import { passportJwtSecret } from 'jwks-rsa';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { buildRequestTargetUri, validateDpopProof } from './dpop.validator';
import { AuthenticatedUser } from './authenticated-user.interface';

interface KeycloakAccessTokenPayload {
  sub: string;
  scope?: string;
  azp?: string;
  preferred_username?: string;
  email?: string;
  aud?: string | string[];
  cnf?: {
    jkt?: string;
  };
}

interface JwksResponse {
  keys: JsonWebKey[];
}

@Injectable()
export class JwtStrategy
  extends PassportStrategy(Strategy)
  implements OnModuleInit
{
  private readonly logger = new Logger(JwtStrategy.name);
  private publicKeysLogged = false;
  private logPublicKeysPromise: Promise<void> | null = null;

  constructor(private readonly configService: ConfigService) {
    const jwksUri = configService.getOrThrow<string>('KEYCLOAK_JWKS_URI');
    const jwksProvider = passportJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 10,
      jwksUri,
    });

    const strategyHolder: { current?: JwtStrategy } = {};

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('DPoP'),
      passReqToCallback: true,
      ignoreExpiration: false,
      issuer: configService.getOrThrow<string>('KEYCLOAK_ISSUER'),
      algorithms: ['RS256'],
      audience: configService.get<string>('KEYCLOAK_AUDIENCE'),
      secretOrKeyProvider: (request, rawJwtToken, done) => {
        void strategyHolder.current
          ?.ensurePublicKeysLogged()
          .then(() => jwksProvider(request, rawJwtToken, done))
          .catch((error: unknown) => {
            done(error instanceof Error ? error : new Error(String(error)));
          });
      },
    });

    strategyHolder.current = this;
  }

  async onModuleInit(): Promise<void> {
    await this.ensurePublicKeysLogged();
  }

  private ensurePublicKeysLogged(): Promise<void> {
    if (!this.logPublicKeysPromise) {
      this.logPublicKeysPromise = this.logPublicKeysFromJwks();
    }

    return this.logPublicKeysPromise;
  }

  private async logPublicKeysFromJwks(): Promise<void> {
    if (this.publicKeysLogged) {
      return;
    }

    const jwksUri = this.configService.getOrThrow<string>('KEYCLOAK_JWKS_URI');
    const response = await fetch(jwksUri);

    if (!response.ok) {
      throw new Error(
        `No se pudo obtener JWKS (${response.status}): ${jwksUri}`,
      );
    }

    const jwks = (await response.json()) as JwksResponse;
    const signingKeys = jwks.keys.filter(
      (key) =>
        key.kty === 'RSA' && (key.use === 'sig' || key.use === undefined),
    );

    if (signingKeys.length === 0) {
      throw new Error(`JWKS sin claves RSA de firma: ${jwksUri}`);
    }

    this.logger.log(
      `Claves publicas Keycloak (PEM) desde ${jwksUri} — antes de validar tokens:`,
    );

    for (const jwk of signingKeys) {
      const pem = createPublicKey({ key: jwk, format: 'jwk' }).export({
        type: 'spki',
        format: 'pem',
      });
      const pemText = typeof pem === 'string' ? pem : pem.toString('utf8');
      const keyId =
        typeof jwk.kid === 'string' || typeof jwk.kid === 'number'
          ? String(jwk.kid)
          : 'unknown';

      console.log(
        `\n----- Keycloak signing key (kid: ${keyId}) -----\n${pemText}`,
      );
    }

    this.publicKeysLogged = true;
  }

  validate(
    request: Request,
    payload: KeycloakAccessTokenPayload,
  ): AuthenticatedUser {
    const accessToken = ExtractJwt.fromAuthHeaderWithScheme('DPoP')(request);
    if (!accessToken) {
      throw new UnauthorizedException('Missing DPoP access token');
    }

    const dpopProof = request.headers.dpop;
    if (typeof dpopProof !== 'string') {
      throw new UnauthorizedException('Missing DPoP proof header');
    }

    const expectedJkt = payload.cnf?.jkt;
    if (!expectedJkt) {
      throw new UnauthorizedException(
        'Access token is not DPoP-bound (missing cnf.jkt)',
      );
    }

    validateDpopProof({
      proof: dpopProof,
      method: request.method,
      url: buildRequestTargetUri(request),
      accessToken,
      expectedJkt,
    });

    const requiredScope = this.configService.get<string>('REQUIRED_SCOPE');

    if (requiredScope) {
      const scopes = payload.scope?.split(' ') ?? [];
      if (!scopes.includes(requiredScope)) {
        throw new UnauthorizedException(
          `Missing required scope: ${requiredScope}`,
        );
      }
    }

    return {
      sub: payload.sub,
      scope: payload.scope,
      azp: payload.azp,
      preferredUsername: payload.preferred_username,
      email: payload.email,
    };
  }
}
