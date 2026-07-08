import * as path from 'path';
import * as dotenv from 'dotenv';

// Must run before importing provision-tenant: it imports controlPlaneDataSource,
// which reads process.env.DATABASE_PORT etc. at module-load time.
dotenv.config({ path: path.resolve(__dirname, '../.env') });

import { provisionTenant } from './provision-tenant';

const ACCESS_CONTROL = 'http://localhost:3001';
const USER_MANAGEMENT = 'http://localhost:3002';
const EXPENSE_MANAGEMENT = 'http://localhost:3003';

const ALL_PERMISSION_KEYS = [
  'user:manage', 'expense:create', 'expense:approve', 'expense:read', 'payroll:run', 'payroll:read',
  'report:create', 'report:read', 'workflow:create', 'workflow:advance', 'notification:send',
  'notification:read', 'invoice:create', 'invoice:read', 'role:manage', 'audit:read',
];

async function post(url: string, body: unknown, headers: Record<string, string> = {}): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`POST ${url} failed: ${res.status} ${await res.text()}`);
  return res.json();
}

async function seedTenant(slug: string, name: string) {
  const { tenantId, serviceApiKeys } = await provisionTenant(slug, name);
  // Identity provisioning here stands in for what ProfilesService.createProfile
  // does in the real flow, so it presents itself as user-management's own key.
  const serviceKeyHeader = { 'x-service-api-key': serviceApiKeys['user-management'] };

  const adminIdentity = await post(
    `${ACCESS_CONTROL}/internal/users`,
    { tenantId, email: `admin@${slug}.example.com`, password: 'hunter22' },
    serviceKeyHeader,
  );

  // The role/org-unit bootstrap calls below happen before the admin has any
  // role assigned yet, so they can't be authorized by a real permission
  // check. A short-lived token signed directly (not via login) carries every
  // permission needed to finish setup — same bootstrap pattern as the e2e
  // test helpers.
  const { signAccessToken } = await import('@platform/auth-kit');
  const bootstrapToken = signAccessToken(
    { sub: adminIdentity.id, tenantId, roles: ['bootstrap'], permissions: ['role:manage'], orgUnitId: null },
    process.env.JWT_SECRET ?? 'dev-secret-change-me',
    300,
  );
  const authHeader = { authorization: `Bearer ${bootstrapToken}` };

  const hq = await post(`${ACCESS_CONTROL}/org-units`, { name: 'HQ', parentId: null }, authHeader);
  await post(`${ACCESS_CONTROL}/org-units`, { name: 'Engineering', parentId: hq.id }, authHeader);
  const finance = await post(`${ACCESS_CONTROL}/org-units`, { name: 'Finance', parentId: hq.id }, authHeader);

  const adminRole = await post(
    `${ACCESS_CONTROL}/roles`,
    { name: 'Admin', permissionKeys: ALL_PERMISSION_KEYS },
    authHeader,
  );
  const financeLeadRole = await post(
    `${ACCESS_CONTROL}/roles`,
    { name: 'Regional Finance Lead', permissionKeys: ['expense:approve', 'payroll:read', 'invoice:read'] },
    authHeader,
  );

  await post(`${ACCESS_CONTROL}/role-assignments`, { userId: adminIdentity.id, roleId: adminRole.id, orgUnitId: hq.id }, authHeader);

  await post(
    `${USER_MANAGEMENT}/profiles`,
    { email: `admin@${slug}.example.com`, password: 'hunter22', fullName: 'Ada Admin', jobTitle: 'Administrator', orgUnitId: hq.id, hireDate: '2024-01-01' },
    authHeader,
  ).catch(() => undefined); // profile creation re-provisions identity by email; ignore duplicate in idempotent re-runs

  const financeLeadIdentity = await post(
    `${ACCESS_CONTROL}/internal/users`,
    { tenantId, email: `finance-lead@${slug}.example.com`, password: 'hunter22' },
    serviceKeyHeader,
  );
  await post(
    `${ACCESS_CONTROL}/role-assignments`,
    { userId: financeLeadIdentity.id, roleId: financeLeadRole.id, orgUnitId: finance.id },
    authHeader,
  );

  const adminLogin = await post(`${ACCESS_CONTROL}/auth/login`, { tenantSlug: slug, email: `admin@${slug}.example.com`, password: 'hunter22' });
  await post(
    `${EXPENSE_MANAGEMENT}/expenses`,
    { orgUnitId: finance.id, amountCents: 4599, description: 'Sample seeded expense' },
    { authorization: `Bearer ${adminLogin.accessToken}` },
  );

  return { slug, tenantId, serviceApiKeys, adminEmail: `admin@${slug}.example.com` };
}

async function main() {
  const results = [];
  for (const [slug, name] of [['acme', 'Acme Corp'], ['globex', 'Globex Corp']] as const) {
    results.push(await seedTenant(slug, name));
  }
  console.log('Seeded tenants:');
  for (const r of results) {
    console.log(`  ${r.slug} (${r.tenantId}) — admin: ${r.adminEmail} / hunter22`);
    for (const [serviceName, key] of Object.entries(r.serviceApiKeys)) {
      console.log(`    ${serviceName}: ${key}`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
