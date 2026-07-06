import jwt from 'jsonwebtoken';

export interface AccessTokenClaims {
  sub: string;
  tenantId: string;
  roles: string[];
  permissions: string[];
  orgUnitId: string | null;
  iat: number;
  exp: number;
}

export class InvalidTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidTokenError';
  }
}

export function signAccessToken(
  payload: {
    sub: string;
    tenantId: string;
    roles: string[];
    permissions: string[];
    orgUnitId: string | null;
  },
  secret: string,
  ttlSeconds: number,
): string {
  return jwt.sign(payload, secret, { expiresIn: ttlSeconds });
}

export function verifyAccessToken(token: string, secret: string): AccessTokenClaims {
  try {
    return jwt.verify(token, secret) as AccessTokenClaims;
  } catch (err) {
    throw new InvalidTokenError((err as Error).message);
  }
}
