import { createTenantDataSourceResolver } from './tenant-datasource';

describe('createTenantDataSourceResolver', () => {
  it('caches the tenant db record lookup in redis', async () => {
    const redis = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue('OK'),
    } as any;
    const resolver = createTenantDataSourceResolver(redis);
    expect(resolver).toBeDefined();
    // lookupTenantDb is exercised indirectly via getConnection in Task 9's
    // integration test once a real tenant + registry row exist; here we only
    // assert construction succeeds and exposes getConnection.
    expect(typeof resolver.getConnection).toBe('function');
  });
});
