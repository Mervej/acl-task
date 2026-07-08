import { processStreamMessage, consumeTenantStream } from './consumer';

describe('processStreamMessage', () => {
  it('parses the audit payload and persists an AuditEventRecord', async () => {
    const saved: any[] = [];
    const repo = { create: (d: any) => d, save: async (e: any) => { saved.push(e); return e; } };
    const fakeDataSource = { getRepository: () => repo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const payload = JSON.stringify({
      tenantId: 'tenant-1', actorUserId: 'user-1', service: 'expense-management',
      action: 'expense.approve', resourceType: 'expense', resourceId: 'expense-1',
      decision: 'allow', timestamp: '2026-01-01T00:00:00.000Z',
    });

    await processStreamMessage(resolver, 'tenant-1', payload);
    expect(saved).toHaveLength(1);
    expect(saved[0].action).toBe('expense.approve');
    expect(saved[0].decision).toBe('allow');
  });
});

describe('consumeTenantStream', () => {
  it('acks each message it successfully processes', async () => {
    const repo = { create: (d: any) => d, save: async () => ({}) };
    const fakeDataSource = { getRepository: () => repo };
    const resolver = { getConnection: jest.fn().mockResolvedValue(fakeDataSource) } as any;

    const payload = JSON.stringify({
      tenantId: 'tenant-1', actorUserId: null, service: 'payroll', action: 'payroll.run',
      resourceType: 'payroll_run', resourceId: 'run-1', decision: 'allow', timestamp: '2026-01-01T00:00:00.000Z',
    });

    const xack = jest.fn().mockResolvedValue(1);
    const redis = {
      xgroup: jest.fn().mockResolvedValue('OK'),
      xreadgroup: jest.fn().mockResolvedValue([
        ['audit:tenant-1', [['1-0', ['payload', payload]]]],
      ]),
      xack,
    } as any;

    await consumeTenantStream(redis, resolver, 'tenant-1', 'audit-service', 'consumer-1');
    expect(xack).toHaveBeenCalledWith('audit:tenant-1', 'audit-service', '1-0');
  });
});
