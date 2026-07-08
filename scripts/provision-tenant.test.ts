import { provisionTenant } from './provision-tenant';
import { controlPlaneDataSource } from '../packages/access-control/src/control-plane/data-source';
import { Tenant, TenantDbRegistry } from '../packages/access-control/src/control-plane/entities';

describe('provisionTenant', () => {
  beforeAll(async () => {
    if (!controlPlaneDataSource.isInitialized) await controlPlaneDataSource.initialize();
  });

  afterAll(async () => {
    await controlPlaneDataSource.destroy();
  });

  it('creates a tenant row and a registry row per provisioned service', async () => {
    const slug = `test-tenant-${Date.now()}`;
    const { tenantId } = await provisionTenant(slug, 'Test Tenant');

    const tenant = await controlPlaneDataSource.getRepository(Tenant).findOne({ where: { id: tenantId } });
    expect(tenant?.slug).toBe(slug);

    const registryRows = await controlPlaneDataSource
      .getRepository(TenantDbRegistry)
      .find({ where: { tenantId } });
    const serviceNames = registryRows.map((r) => r.serviceName).sort();
    expect(serviceNames).toEqual(['access-control', 'audit', 'expense-management', 'payroll', 'user-management']);
  });

  it('returns a distinct, non-empty api key per internal service', async () => {
    const slug = `test-tenant-key-${Date.now()}`;
    const { serviceApiKeys } = await provisionTenant(slug, 'Test Tenant Key');
    const keys = Object.values(serviceApiKeys);
    expect(keys.length).toBeGreaterThan(1);
    for (const key of keys) {
      expect(typeof key).toBe('string');
      expect(key.length).toBeGreaterThan(0);
    }
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('derives each service key from its own env var so demo tenants can be reseeded without extra config', async () => {
    const slugA = `test-tenant-stable-a-${Date.now()}`;
    const slugB = `test-tenant-stable-b-${Date.now()}`;
    const a = await provisionTenant(slugA, 'Tenant A');
    const b = await provisionTenant(slugB, 'Tenant B');
    expect(a.serviceApiKeys.payroll).toBe(b.serviceApiKeys.payroll);
  });
});
