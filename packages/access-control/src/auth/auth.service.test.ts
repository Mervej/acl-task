import { AuthService } from './auth.service';

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
