import { ProfilesService } from './profiles.service';

const originalFetch = global.fetch;

describe('ProfilesService.createProfile', () => {
  afterEach(() => { global.fetch = originalFetch; });

  it('provisions the identity via Access Control then stores the local profile', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: 'user-1', email: 'alice@example.com' }),
    }) as any;

    const savedRows: any[] = [];
    const fakeRepo = {
      create: (data: any) => ({ id: 'profile-1', ...data }),
      save: async (e: any) => { savedRows.push(e); return e; },
      findOne: async () => null,
      find: async () => [],
    };
    const fakeDataSource = { getRepository: () => fakeRepo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new ProfilesService(resolver, 'http://localhost:3001', 'test-key');
    const profile = await service.createProfile({
      tenantId: 'tenant-1', email: 'alice@example.com', password: 'hunter22',
      fullName: 'Alice Example', jobTitle: 'Engineer', orgUnitId: null, managerId: null,
      hireDate: '2026-01-01',
    });

    expect(profile.userId).toBe('user-1');
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:3001/internal/users',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(savedRows).toHaveLength(1);
  });
});
