import { PermissionCheckClient } from './permission-check-client';
import type { AccessTokenClaims } from './jwt';

describe('PermissionCheckClient.check (fast path)', () => {
  const client = new PermissionCheckClient({
    accessControlBaseUrl: 'http://localhost:3001',
    serviceApiKey: 'test-key',
  });

  const claims: AccessTokenClaims = {
    sub: 'user-1',
    tenantId: 'tenant-1',
    roles: ['manager'],
    permissions: ['expense:approve'],
    orgUnitId: 'org-1',
    iat: 0,
    exp: 0,
  };

  it('allows when the permission is present and org unit matches', () => {
    expect(client.check(claims, 'expense:approve', 'org-1')).toBe(true);
  });

  it('denies when the permission is missing', () => {
    expect(client.check(claims, 'payroll:run', 'org-1')).toBe(false);
  });

  it('denies when the target org unit differs and claims.orgUnitId is set', () => {
    expect(client.check(claims, 'expense:approve', 'org-2')).toBe(false);
  });

  it('allows when no target org unit is specified', () => {
    expect(client.check(claims, 'expense:approve', null)).toBe(true);
  });
});
