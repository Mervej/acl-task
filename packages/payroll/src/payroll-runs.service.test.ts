import { PayrollRunsService } from './payroll-runs.service';

describe('PayrollRunsService.trigger', () => {
  it('creates a payroll run and a flat-amount payslip per employee', async () => {
    const runs: any[] = [];
    const slips: any[] = [];
    const runRepo = {
      create: (d: any) => ({ id: 'run-1', ...d }),
      save: async (e: any) => { runs.push(e); return e; },
    };
    const slipRepo = {
      create: (d: any) => d,
      save: async (entities: any[]) => { slips.push(...entities); return entities; },
    };
    const fakeDataSource = {
      getRepository: (entity: any) => (entity.name === 'PayrollRun' ? runRepo : slipRepo),
    };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const service = new PayrollRunsService(resolver);
    const run = await service.trigger('tenant-1', 'org-1', 'user-1', ['emp-1', 'emp-2']);

    expect(run.totalAmountCents).toBe(1000000);
    expect(slips).toHaveLength(2);
    expect(slips.every((s) => s.amountCents === 500000)).toBe(true);
  });
});
