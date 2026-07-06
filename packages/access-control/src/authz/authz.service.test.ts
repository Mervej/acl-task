import { AuthzService } from './authz.service';

describe('AuthzService.check', () => {
  it('allows when the user has the permission and the target org unit is a descendant of their scope', async () => {
    const orgUnits = [
      { id: 'root', parentId: null },
      { id: 'org-1', parentId: 'root' },
      { id: 'org-1-a', parentId: 'org-1' },
    ];
    const fakeDataSource = { getRepository: () => ({ find: async () => orgUnits }) };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;
    const authService = {
      resolveEffectivePermissions: jest.fn().mockResolvedValue({
        roles: ['Manager'], permissions: ['expense:approve'], orgUnitId: 'org-1',
      }),
    } as any;
    const usersService = {} as any;

    const service = new AuthzService(resolver, authService, usersService);
    expect(await service.check('t1', 'u1', 'expense:approve', 'org-1-a')).toBe(true);
    expect(await service.check('t1', 'u1', 'payroll:run', 'org-1-a')).toBe(false);
  });

  it('denies when the target org unit is outside the user\'s scope', async () => {
    const orgUnits = [
      { id: 'org-1', parentId: null },
      { id: 'org-2', parentId: null },
    ];
    const fakeDataSource = { getRepository: () => ({ find: async () => orgUnits }) };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;
    const authService = {
      resolveEffectivePermissions: jest.fn().mockResolvedValue({
        roles: ['Manager'], permissions: ['expense:approve'], orgUnitId: 'org-1',
      }),
    } as any;
    const service = new AuthzService(resolver, authService, {} as any);
    expect(await service.check('t1', 'u1', 'expense:approve', 'org-2')).toBe(false);
  });
});
