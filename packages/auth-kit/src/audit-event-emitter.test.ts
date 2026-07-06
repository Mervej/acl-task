import { AuditEventEmitter } from './audit-event-emitter';

describe('AuditEventEmitter', () => {
  it('XADDs a JSON-serialized payload to the tenant stream', async () => {
    const xadd = jest.fn().mockResolvedValue('1-0');
    const redis = { xadd } as any;
    const emitter = new AuditEventEmitter(redis);

    await emitter.emit({
      tenantId: 'tenant-1',
      actorUserId: 'user-1',
      service: 'expense-management',
      action: 'expense.approve',
      resourceType: 'expense',
      resourceId: 'expense-42',
      decision: 'allow',
    });

    expect(xadd).toHaveBeenCalledWith(
      'audit:tenant-1',
      '*',
      'payload',
      expect.stringContaining('"action":"expense.approve"'),
    );
  });
});
