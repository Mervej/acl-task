import type { AccessTokenClaims } from './jwt';

export function serviceApiKeyEnvVar(serviceName: string): string {
  return `SERVICE_API_KEY_${serviceName.toUpperCase().replace(/-/g, '_')}`;
}

export function resolveOwnServiceApiKey(serviceName: string): string {
  return process.env[serviceApiKeyEnvVar(serviceName)] ?? `dev-service-key-${serviceName}`;
}

export class PermissionCheckClient {
  private readonly accessControlBaseUrl: string;
  private readonly serviceApiKey: string;

  constructor(opts: { accessControlBaseUrl: string; serviceApiKey: string }) {
    this.accessControlBaseUrl = opts.accessControlBaseUrl;
    this.serviceApiKey = opts.serviceApiKey;
  }

  check(
    claims: AccessTokenClaims,
    permission: string,
    targetOrgUnitId: string | null,
  ): boolean {
    if (!claims.permissions.includes(permission)) return false;
    if (targetOrgUnitId === null || claims.orgUnitId === null) return true;
    return claims.orgUnitId === targetOrgUnitId;
  }

  async checkLive(
    tenantId: string,
    userId: string,
    permission: string,
    orgUnitId: string | null,
  ): Promise<boolean> {
    const res = await fetch(`${this.accessControlBaseUrl}/authz/check`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-service-api-key': this.serviceApiKey,
      },
      body: JSON.stringify({ tenantId, userId, permission, orgUnitId }),
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { allowed: boolean };
    return body.allowed;
  }

  async verifyServiceKey(tenantId: string, key: string): Promise<boolean> {
    const res = await fetch(`${this.accessControlBaseUrl}/authz/verify-service-key`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tenantId, key }),
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { valid: boolean };
    return body.valid;
  }
}
