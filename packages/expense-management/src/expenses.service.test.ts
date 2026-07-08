import { ExpensesService } from './expenses.service';

const originalFetch = global.fetch;

describe('ExpensesService.approve', () => {
  afterEach(() => { global.fetch = originalFetch; });

  it('calls Payroll and marks the expense approved on success', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'recorded' }) }) as any;

    const expense = { id: 'expense-1', tenantId: 'tenant-1', status: 'pending', amountCents: 5000 };
    const fakeRepo = {
      findOne: async () => expense,
      save: async (e: any) => { Object.assign(expense, e); return expense; },
    };
    const fakeDataSource = { getRepository: () => fakeRepo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new ExpensesService(resolver, 'http://localhost:3004');
    const result = await service.approve('tenant-1', 'expense-1', 'Bearer sometoken', 'service-key');

    expect(result.status).toBe('approved');
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:3004/reimbursements',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({ authorization: 'Bearer sometoken', 'x-service-api-key': 'service-key' }),
      }),
    );
  });

  it('leaves the expense pending when Payroll rejects the call', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 403 }) as any;

    const expense = { id: 'expense-2', tenantId: 'tenant-1', status: 'pending', amountCents: 1000 };
    const fakeRepo = { findOne: async () => expense, save: async (e: any) => e };
    const fakeDataSource = { getRepository: () => fakeRepo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new ExpensesService(resolver, 'http://localhost:3004');
    await expect(service.approve('tenant-1', 'expense-2', 'Bearer sometoken', 'service-key')).rejects.toThrow();
    expect(expense.status).toBe('pending');
  });
});
