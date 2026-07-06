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
      destroy: jest.fn().mockResolvedValue(undefined),
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
    const destroyA = jest.fn().mockResolvedValue(undefined);
    const destroyB = jest.fn().mockResolvedValue(undefined);
    jest
      .spyOn(resolver as any, 'createDataSource')
      .mockResolvedValueOnce({ isInitialized: true, destroy: destroyA })
      .mockResolvedValueOnce({ isInitialized: true, destroy: destroyB });
    await resolver.getConnection('tenant-1');
    await resolver.getConnection('tenant-2');
    expect(destroyA).toHaveBeenCalled();
  });

  it('de-dupes concurrent getConnection calls for the same uncached tenant', async () => {
    const lookupTenantDb = jest.fn().mockResolvedValue({
      host: 'localhost', port: 5432, database: 'db', username: 'u', password: 'p',
    });
    const resolver = new TenantConnectionResolver({
      serviceName: 'test-service',
      entities: [] as unknown as Function[],
      lookupTenantDb,
    });
    const spy = jest
      .spyOn(resolver as any, 'createDataSource')
      .mockResolvedValue({ isInitialized: true, destroy: jest.fn().mockResolvedValue(undefined) });

    // Two concurrent calls for the same brand-new tenant should share a single
    // in-flight creation instead of each racing to create their own DataSource.
    const [a, b] = await Promise.all([
      resolver.getConnection('tenant-concurrent'),
      resolver.getConnection('tenant-concurrent'),
    ]);

    expect(a).toBe(b);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(lookupTenantDb).toHaveBeenCalledTimes(1);
  });

  it('handles rejected destroy() during eviction without throwing', async () => {
    const lookupTenantDb = jest.fn().mockResolvedValue({
      host: 'localhost', port: 5432, database: 'db', username: 'u', password: 'p',
    });
    const resolver = new TenantConnectionResolver({
      serviceName: 'test-service',
      entities: [] as unknown as Function[],
      lookupTenantDb,
      maxOpenConnections: 1,
    });
    const destroyError = new Error('Network error');
    const destroyA = jest.fn().mockRejectedValue(destroyError);
    const destroyB = jest.fn().mockResolvedValue(undefined);
    jest
      .spyOn(resolver as any, 'createDataSource')
      .mockResolvedValueOnce({ isInitialized: true, destroy: destroyA })
      .mockResolvedValueOnce({ isInitialized: true, destroy: destroyB });

    const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

    // Create two connections; the second evicts the first, whose destroy() rejects.
    // This should not throw or create an unhandled rejection.
    await resolver.getConnection('tenant-1');
    await resolver.getConnection('tenant-2');

    // Verify the rejection was caught and logged.
    expect(destroyA).toHaveBeenCalled();
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Failed to destroy connection for tenant tenant-1'),
      destroyError,
    );

    consoleErrorSpy.mockRestore();
  });
});
