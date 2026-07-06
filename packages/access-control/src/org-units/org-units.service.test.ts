import { OrgUnitsService } from './org-units.service';

describe('OrgUnitsService', () => {
  it('creates an org unit and lists it back for the tenant', async () => {
    const rows: any[] = [];
    const fakeRepo = {
      create: (data: any) => ({ id: `org-${rows.length + 1}`, ...data }),
      save: async (entity: any) => { rows.push(entity); return entity; },
      find: async ({ where }: any) => rows.filter((r) => r.tenantId === where.tenantId),
    };
    const fakeDataSource = { getRepository: () => fakeRepo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new OrgUnitsService(resolver);
    await service.create('tenant-1', 'Engineering', null);
    const list = await service.list('tenant-1');
    expect(list).toHaveLength(1);
    expect(list[0].name).toBe('Engineering');
  });
});
