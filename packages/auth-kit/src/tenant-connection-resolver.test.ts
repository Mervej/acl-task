import { TenantConnectionResolver } from './tenant-connection-resolver';
import { EntitySchema } from 'typeorm';

describe('TenantConnectionResolver', () => {
  it('reuses a cached connection for the same tenant', async () => {
    const lookupTenantDb = jest.fn().mockResolvedValue({
      host: 'localhost',
      port: 5432,
      database: 'test_db',
      username: 'postgres',
      password: 'postgres',
    });
    const resolver = new TenantConnectionResolver({
      serviceName: 'test-service',
      entities: [] as unknown as Function[],
      lookupTenantDb,
    });
    // Both calls resolve to the same DataSource instance without re-initializing.
    const spy = jest.spyOn(resolver as any, 'createDataSource').mockResolvedValue({
      isInitialized: true,
      destroy: jest.fn(),
    });
    const a = await resolver.getConnection('tenant-1');
    const b = await resolver.getConnection('tenant-1');
    expect(a).toBe(b);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(lookupTenantDb).toHaveBeenCalledWith('tenant-1');
  });

  it('evicts the least-recently-used connection past maxOpenConnections', async () => {
    const lookupTenantDb = jest.fn().mockResolvedValue({
      host: 'localhost', port: 5432, database: 'db', username: 'u', password: 'p',
    });
    const resolver = new TenantConnectionResolver({
      serviceName: 'test-service',
      entities: [] as unknown as Function[],
      lookupTenantDb,
      maxOpenConnections: 1,
    });
    const destroyA = jest.fn();
    const destroyB = jest.fn();
    jest
      .spyOn(resolver as any, 'createDataSource')
      .mockResolvedValueOnce({ isInitialized: true, destroy: destroyA })
      .mockResolvedValueOnce({ isInitialized: true, destroy: destroyB });
    await resolver.getConnection('tenant-1');
    await resolver.getConnection('tenant-2');
    expect(destroyA).toHaveBeenCalled();
  });
});
