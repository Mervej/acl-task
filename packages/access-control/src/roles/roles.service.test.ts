import { RolesService } from './roles.service';

describe('RolesService', () => {
  it('creates a custom role with an arbitrary permission subset and lists it back', async () => {
    const roleRows: any[] = [];
    const rolePermissionRows: any[] = [];
    const fakeRoleRepo = {
      create: (data: any) => ({ id: 'role-1', ...data }),
      save: async (e: any) => { roleRows.push(e); return e; },
      find: async ({ where }: any) => roleRows.filter((r) => r.tenantId === where.tenantId),
    };
    const fakeRolePermissionRepo = {
      create: (data: any) => data,
      save: async (entities: any[]) => { rolePermissionRows.push(...entities); return entities; },
      find: async ({ where }: any) => rolePermissionRows.filter((rp) => where.roleId.value.includes(rp.roleId)),
    };
    const fakeDataSource = {
      getRepository: (entity: any) => (entity.name === 'Role' ? fakeRoleRepo : fakeRolePermissionRepo),
    };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new RolesService(resolver);
    const created = await service.createRole('tenant-1', 'Regional Finance Lead', '', ['expense:approve', 'payroll:read']);
    expect(created.permissionKeys.sort()).toEqual(['expense:approve', 'payroll:read']);

    const list = await service.listRoles('tenant-1');
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe('Regional Finance Lead');
  });
});
