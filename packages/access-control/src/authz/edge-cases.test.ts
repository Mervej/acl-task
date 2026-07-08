jest.mock('../control-plane/data-source', () => ({
  controlPlaneDataSource: { getRepository: jest.fn() },
}));

import { AuthService } from '../auth/auth.service';
import { AuthzService } from './authz.service';
import { controlPlaneDataSource } from '../control-plane/data-source';
import { UnauthorizedException } from '@nestjs/common';

describe('permission-evaluation edge cases', () => {
  it('rejects login for a deactivated user even with the correct password', async () => {
    // AuthService.login first resolves the tenant from controlPlaneDataSource,
    // then filters on status: 'active' in its per-tenant User lookup (Task 10),
    // so a disabled user simply isn't found — verified here via a fake repo that
    // only returns active users, matching the real query's WHERE clause.
    (controlPlaneDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue({ id: 'tenant-1', slug: 'acme', status: 'active' }),
    });
    const fakeUserRepo = { findOne: async () => null };
    const fakeDataSource = { getRepository: () => fakeUserRepo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;
    const service = new AuthService(resolver, 'secret', 900);

    await expect(service.login('acme', 'disabled-user@acme.example.com', 'anypassword')).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('reflects a role assignment removed mid-session on the slow authz-check path', async () => {
    // Simulates: user had 'expense:approve' when their JWT was issued, but an
    // admin has since deleted their RoleAssignment row. The fast JWT-claims
    // path (PermissionCheckClient.check in auth-kit) would still say "allowed"
    // until the token expires (spec §3 assumption 4's accepted staleness
    // window) — but the slow path here, which re-queries the tenant DB on
    // every call, must reflect the revocation immediately.
    const fakeAssignmentRepo = { find: async () => [] }; // assignment already deleted
    const fakeDataSource = { getRepository: () => fakeAssignmentRepo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;
    const authService = new AuthService(resolver, 'secret', 900);
    const usersService = {} as any;

    const authzService = new AuthzService(resolver, authService, usersService);
    const allowed = await authzService.check('tenant-1', 'user-1', 'expense:approve', null);
    expect(allowed).toBe(false);
  });

  it('does not throw and denies when the target org unit no longer exists', async () => {
    // Simulates: the org unit a resource belonged to was deleted, but the
    // resource's stored orgUnitId still points at the now-missing id.
    const orgUnits = [{ id: 'org-1', parentId: null }]; // 'org-deleted' is absent
    const fakeDataSource = { getRepository: () => ({ find: async () => orgUnits }) };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;
    const authService = {
      resolveEffectivePermissions: jest.fn().mockResolvedValue({
        roles: ['Manager'], permissions: ['expense:approve'], orgUnitId: 'org-1',
      }),
    } as any;

    const authzService = new AuthzService(resolver, authService, {} as any);
    const allowed = await authzService.check('tenant-1', 'user-1', 'expense:approve', 'org-deleted');
    expect(allowed).toBe(false);
  });
});
