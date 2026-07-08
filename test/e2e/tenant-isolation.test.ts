import { setUpTenantWithManager } from './helpers';

describe('tenant isolation', () => {
  it('never lets Tenant A read Tenant B\'s expense, even knowing its real id', async () => {
    const tenantA = await setUpTenantWithManager(`e2e-iso-a-${Date.now()}`);
    const tenantB = await setUpTenantWithManager(`e2e-iso-b-${Date.now()}`);

    const createRes = await fetch('http://localhost:3003/expenses', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${tenantB.accessToken}` },
      body: JSON.stringify({ orgUnitId: tenantB.orgUnitId, amountCents: 999, description: 'Tenant B secret expense' }),
    });
    const tenantBExpense = await createRes.json();

    // Tenant A's own token always resolves to Tenant A's own database — there is
    // no tenantId the client can supply on this route, so the only way Tenant A
    // could see Tenant B's expense is if the id happened to also exist in
    // Tenant A's own (separate) database, which it can't.
    const crossTenantRead = await fetch(`http://localhost:3003/expenses/${tenantBExpense.id}`, {
      headers: { authorization: `Bearer ${tenantA.accessToken}` },
    });
    expect(crossTenantRead.status).toBe(404);
  });

  it('never lets Tenant A read Tenant B\'s payroll run', async () => {
    const tenantA = await setUpTenantWithManager(`e2e-iso-payroll-a-${Date.now()}`);
    const tenantB = await setUpTenantWithManager(`e2e-iso-payroll-b-${Date.now()}`);

    const runRes = await fetch('http://localhost:3004/payroll-runs', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${tenantB.accessToken}` },
      body: JSON.stringify({ orgUnitId: tenantB.orgUnitId, employeeUserIds: ['emp-1'] }),
    });
    const tenantBRun = await runRes.json();

    const crossTenantRead = await fetch(`http://localhost:3004/payroll-runs/${tenantBRun.id}`, {
      headers: { authorization: `Bearer ${tenantA.accessToken}` },
    });
    expect(crossTenantRead.status).toBe(404);
  });
});
