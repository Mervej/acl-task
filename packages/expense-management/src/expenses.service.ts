import { Injectable, NotFoundException } from '@nestjs/common';
import Redis from 'ioredis';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { AuditEventEmitter } from '@platform/auth-kit';
import { Expense } from './entities';

const auditEmitter = new AuditEventEmitter(new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379'));

@Injectable()
export class ExpensesService {
  constructor(
    private readonly resolver: TenantConnectionResolver,
    private readonly payrollBaseUrl: string,
  ) {}

  async create(
    tenantId: string,
    orgUnitId: string | null,
    createdByUserId: string,
    amountCents: number,
    description: string,
  ): Promise<Expense> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const repo = dataSource.getRepository(Expense);
    const saved = await repo.save(repo.create({ tenantId, orgUnitId, createdByUserId, amountCents, description, status: 'pending' }));
    await auditEmitter.emit({
      tenantId, actorUserId: createdByUserId, service: 'expense-management',
      action: 'expense.create', resourceType: 'expense', resourceId: saved.id, decision: 'allow',
    });
    return saved;
  }

  async get(tenantId: string, id: string): Promise<Expense | null> {
    const dataSource = await this.resolver.getConnection(tenantId);
    return dataSource.getRepository(Expense).findOne({ where: { id, tenantId } });
  }

  async list(tenantId: string, orgUnitId?: string): Promise<Expense[]> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const where: Record<string, unknown> = { tenantId };
    if (orgUnitId) where.orgUnitId = orgUnitId;
    return dataSource.getRepository(Expense).find({ where });
  }

  async approve(
    tenantId: string,
    id: string,
    authorizationHeader: string,
    serviceApiKey: string,
  ): Promise<Expense> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const repo = dataSource.getRepository(Expense);
    const expense = await repo.findOne({ where: { id, tenantId } });
    if (!expense) throw new NotFoundException('Expense not found');

    const res = await fetch(`${this.payrollBaseUrl}/reimbursements`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: authorizationHeader,
        'x-service-api-key': serviceApiKey,
      },
      body: JSON.stringify({ tenantId, expenseId: id, amountCents: expense.amountCents }),
    });
    if (!res.ok) {
      throw new Error(`Payroll rejected the reimbursement call: ${res.status}`);
    }

    expense.status = 'approved';
    const saved = await repo.save(expense);
    await auditEmitter.emit({
      tenantId, actorUserId: null, service: 'expense-management',
      action: 'expense.approve', resourceType: 'expense', resourceId: id, decision: 'allow', viaService: 'payroll',
    });
    return saved;
  }
}
