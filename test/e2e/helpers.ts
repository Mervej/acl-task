import { provisionTenant } from '../../scripts/provision-tenant';
import { signAccessToken } from '@platform/auth-kit';

const ACCESS_CONTROL = 'http://localhost:3001';

async function post(url: string, body: unknown, headers: Record<string, string> = {}): Promise<any> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`POST ${url} failed: ${res.status} ${await res.text()}`);
  return res.json();
}

// The role/org-unit bootstrap calls below happen before the user has any role
// assigned yet, so they can't be authorized by a real permission check. For
// this reference implementation, the very first bootstrap call for a fresh
// tenant signs a short-lived token directly (not via login) carrying every
// permission needed to finish setup. Real tenant onboarding in production
// would instead pre-seed a system "Tenant Admin" role at provisioning time
// (documented as a follow-up in the design spec's §9).
async function bootstrapAuthHeader(tenantId: string, userId: string): Promise<Record<string, string>> {
  const token = signAccessToken(
    { sub: userId, tenantId, roles: ['bootstrap'], permissions: ['role:manage'], orgUnitId: null },
    process.env.JWT_SECRET ?? 'dev-secret-change-me',
    300,
  );
  return { authorization: `Bearer ${token}` };
}

export async function setUpTenantWithManager(
  slug: string,
): Promise<{ tenantId: string; serviceApiKey: string; orgUnitId: string; accessToken: string }> {
  const { tenantId, serviceApiKey } = await provisionTenant(slug, slug);

  const user = await post(
    `${ACCESS_CONTROL}/internal/users`,
    { tenantId, email: `manager@${slug}.example.com`, password: 'hunter22' },
    { 'x-service-api-key': serviceApiKey },
  );

  const bootstrapHeader = await bootstrapAuthHeader(tenantId, user.id);

  const orgUnit = await post(`${ACCESS_CONTROL}/org-units`, { name: 'HQ', parentId: null }, bootstrapHeader);

  const role = await post(
    `${ACCESS_CONTROL}/roles`,
    {
      name: 'Manager',
      permissionKeys: ['expense:create', 'expense:approve', 'payroll:run', 'user:manage', 'role:manage'],
    },
    bootstrapHeader,
  );

  await post(
    `${ACCESS_CONTROL}/role-assignments`,
    { userId: user.id, roleId: role.id, orgUnitId: orgUnit.id },
    bootstrapHeader,
  );

  const login = await post(`${ACCESS_CONTROL}/auth/login`, {
    tenantSlug: slug,
    email: `manager@${slug}.example.com`,
    password: 'hunter22',
  });

  return { tenantId, serviceApiKey, orgUnitId: orgUnit.id, accessToken: login.accessToken };
}
