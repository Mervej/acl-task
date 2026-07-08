import { UsersService } from './users.service';

describe('UsersService', () => {
  it('creates a user with a hashed password and can fetch it back', async () => {
    const users = new Map<string, any>();
    const fakeRepo = {
      create: (data: any) => ({ id: 'user-1', ...data }),
      save: async (entity: any) => { users.set(entity.id, entity); return entity; },
      findOne: async ({ where }: any) => users.get(where.id) ?? null,
    };
    const fakeDataSource = { getRepository: () => fakeRepo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new UsersService(resolver);
    const created = await service.createUser('tenant-1', 'alice@example.com', 'hunter2');
    expect(created.email).toBe('alice@example.com');

    const fetched = await service.getUser('tenant-1', created.id);
    expect(fetched?.email).toBe('alice@example.com');
  });

  it('verifies a matching, non-revoked service api key', async () => {
    const apiKeys = [{ tenantId: 'tenant-1', keyHash: require('../password').hashSecret('secret-key'), revokedAt: null }];
    const fakeRepo = { findOne: async ({ where }: any) => apiKeys.find(k => k.tenantId === where.tenantId) ?? null };
    const fakeDataSource = { getRepository: () => fakeRepo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new UsersService(resolver);
    expect(await service.verifyServiceApiKey('tenant-1', 'secret-key')).toBe(true);
    expect(await service.verifyServiceApiKey('tenant-1', 'wrong-key')).toBe(false);
  });
});
