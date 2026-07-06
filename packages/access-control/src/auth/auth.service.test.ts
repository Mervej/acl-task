import bcrypt from 'bcrypt';
import { UnauthorizedException } from '@nestjs/common';

jest.mock('../control-plane/data-source', () => ({
  controlPlaneDataSource: { getRepository: jest.fn() },
}));

import { AuthService } from './auth.service';
import { controlPlaneDataSource } from '../control-plane/data-source';

describe('AuthService.resolveEffectivePermissions', () => {
  it('flattens role assignments into a permission set and picks an org unit', async () => {
    const roleAssignments = [{ tenantId: 't1', userId: 'u1', roleId: 'r1', orgUnitId: 'org-1' }];
    const rolePermissions = [
      { roleId: 'r1', permissionKey: 'expense:approve' },
      { roleId: 'r1', permissionKey: 'expense:read' },
    ];
    const roles = [{ id: 'r1', tenantId: 't1', name: 'Manager' }];

    const fakeDataSource = {
      getRepository: (entity: any) => {
        if (entity.name === 'RoleAssignment') return { find: async () => roleAssignments };
        if (entity.name === 'RolePermission')
          return {
            // TypeORM's `In([...])` returns a FindOperator with a `.value` array,
            // not a plain array — reflect that shape here.
            find: async ({ where }: any) =>
              rolePermissions.filter((rp) => where.roleId.value.includes(rp.roleId)),
          };
        if (entity.name === 'Role') return { find: async () => roles };
        throw new Error('unexpected entity');
      },
    };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new AuthService(resolver, 'secret', 900);
    const result = await service.resolveEffectivePermissions('t1', 'u1');
    expect(result.permissions.sort()).toEqual(['expense:approve', 'expense:read']);
    expect(result.roles).toEqual(['Manager']);
    expect(result.orgUnitId).toBe('org-1');
  });
});

describe('AuthService.login timing-safe user lookup', () => {
  const tenant = { id: 't1', slug: 'acme', status: 'active' };

  function mockTenantRepo() {
    (controlPlaneDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(tenant),
    });
  }

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('still performs a bcrypt comparison (against a dummy hash) when the user does not exist', async () => {
    mockTenantRepo();
    const compareSpy = jest.spyOn(bcrypt, 'compare');

    const fakeDataSource = {
      getRepository: (entity: any) => {
        if (entity.name === 'User') return { findOne: async () => null };
        throw new Error('unexpected entity');
      },
    };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;
    const service = new AuthService(resolver, 'secret', 900);

    await expect(service.login('acme', 'nobody@example.com', 'whatever')).rejects.toThrow(
      UnauthorizedException,
    );

    expect(compareSpy).toHaveBeenCalledTimes(1);
    const [comparedPlain, comparedHash] = compareSpy.mock.calls[0];
    expect(comparedPlain).toBe('whatever');
    // Dummy hash must not be the (nonexistent) user's hash — it's the fixed
    // module-level constant used whenever no user was found.
    expect(typeof comparedHash).toBe('string');
    expect(comparedHash).not.toBe('');
  });

  it('performs a bcrypt comparison against the real hash when the user exists but the password is wrong', async () => {
    mockTenantRepo();
    const compareSpy = jest.spyOn(bcrypt, 'compare');
    const realHash = await bcrypt.hash('correct-horse-battery-staple', 10);

    const fakeDataSource = {
      getRepository: (entity: any) => {
        if (entity.name === 'User')
          return { findOne: async () => ({ id: 'u1', passwordHash: realHash }) };
        throw new Error('unexpected entity');
      },
    };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;
    const service = new AuthService(resolver, 'secret', 900);

    await expect(service.login('acme', 'user@example.com', 'wrong-password')).rejects.toThrow(
      UnauthorizedException,
    );

    expect(compareSpy).toHaveBeenCalledTimes(1);
    const [comparedPlain, comparedHash] = compareSpy.mock.calls[0];
    expect(comparedPlain).toBe('wrong-password');
    expect(comparedHash).toBe(realHash);
  });

  it('uses the same dummy hash across calls when the user is not found (precomputed, not re-hashed per request)', async () => {
    mockTenantRepo();
    const compareSpy = jest.spyOn(bcrypt, 'compare');

    const fakeDataSource = {
      getRepository: (entity: any) => {
        if (entity.name === 'User') return { findOne: async () => null };
        throw new Error('unexpected entity');
      },
    };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;
    const service = new AuthService(resolver, 'secret', 900);

    await expect(service.login('acme', 'a@example.com', 'p1')).rejects.toThrow(
      UnauthorizedException,
    );
    await expect(service.login('acme', 'b@example.com', 'p2')).rejects.toThrow(
      UnauthorizedException,
    );

    const hashUsedFirstCall = compareSpy.mock.calls[0][1];
    const hashUsedSecondCall = compareSpy.mock.calls[1][1];
    expect(hashUsedFirstCall).toBe(hashUsedSecondCall);
  });
});
