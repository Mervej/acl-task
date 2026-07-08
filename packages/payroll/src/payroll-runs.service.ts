import { Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { AuditEventEmitter } from '@platform/auth-kit';
import { PayrollRun, Payslip } from './entities';

const auditEmitter = new AuditEventEmitter(new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379'));
const FLAT_SALARY_CENTS_PER_EMPLOYEE = 500000;

@Injectable()
export class PayrollRunsService {
  constructor(private readonly resolver: TenantConnectionResolver) {}

  async trigger(
    tenantId: string,
    orgUnitId: string | null,
    triggeredByUserId: string,
    employeeUserIds: string[],
  ): Promise<PayrollRun> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const runRepo = dataSource.getRepository(PayrollRun);
    const totalAmountCents = employeeUserIds.length * FLAT_SALARY_CENTS_PER_EMPLOYEE;
    const run = await runRepo.save(
      runRepo.create({ tenantId, orgUnitId, triggeredByUserId, status: 'completed', totalAmountCents }),
    );

    const slipRepo = dataSource.getRepository(Payslip);
    const slips = employeeUserIds.map((employeeUserId) =>
      slipRepo.create({ tenantId, payrollRunId: run.id, employeeUserId, amountCents: FLAT_SALARY_CENTS_PER_EMPLOYEE }),
    );
    await slipRepo.save(slips);

    await auditEmitter.emit({
      tenantId, actorUserId: triggeredByUserId, service: 'payroll',
      action: 'payroll.run', resourceType: 'payroll_run', resourceId: run.id, decision: 'allow',
    });

    return run;
  }

  async get(tenantId: string, id: string): Promise<PayrollRun | null> {
    const dataSource = await this.resolver.getConnection(tenantId);
    return dataSource.getRepository(PayrollRun).findOne({ where: { id, tenantId } });
  }

  async list(tenantId: string, orgUnitId?: string): Promise<PayrollRun[]> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const where: Record<string, unknown> = { tenantId };
    if (orgUnitId) where.orgUnitId = orgUnitId;
    return dataSource.getRepository(PayrollRun).find({ where });
  }
}
