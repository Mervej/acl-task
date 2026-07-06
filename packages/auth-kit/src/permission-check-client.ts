import type { AccessTokenClaims } from './jwt';

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
}
