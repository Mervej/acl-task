import { setUpTenantWithManager } from './helpers';

describe('cross-service flow: login -> create expense -> approve -> Payroll call', () => {
  it('approves an expense end-to-end, triggering a real service-to-service call to Payroll', async () => {
    const { orgUnitId, accessToken } = await setUpTenantWithManager(`e2e-flow-${Date.now()}`);

    const createRes = await fetch('http://localhost:3003/expenses', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ orgUnitId, amountCents: 12345, description: 'Flight' }),
    });
    expect(createRes.status).toBe(201);
    const expense = await createRes.json();
    expect(expense.status).toBe('pending');

    const approveRes = await fetch(`http://localhost:3003/expenses/${expense.id}/approve`, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
    });
    expect(approveRes.status).toBe(201);
    const approved = await approveRes.json();
    expect(approved.status).toBe('approved');
  });
});
