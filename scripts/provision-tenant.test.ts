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
    expect(serviceNames).toEqual(['access-control', 'expense-management', 'user-management']);
  });

  it('returns a service api key that other services can verify against', async () => {
    const slug = `test-tenant-key-${Date.now()}`;
    const { tenantId, serviceApiKey } = await provisionTenant(slug, 'Test Tenant Key');
    expect(typeof serviceApiKey).toBe('string');
    expect(serviceApiKey.length).toBeGreaterThan(0);
  });
});
