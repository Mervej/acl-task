import { Injectable } from '@nestjs/common';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { AuditEventRecord } from './entities';

@Injectable()
export class AuditEventsService {
  constructor(private readonly resolver: TenantConnectionResolver) {}

  async list(
    tenantId: string,
    filters: { service?: string; decision?: 'allow' | 'deny' } = {},
  ): Promise<AuditEventRecord[]> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const where: Record<string, unknown> = { tenantId };
    if (filters.service) where.service = filters.service;
    if (filters.decision) where.decision = filters.decision;
    return dataSource.getRepository(AuditEventRecord).find({ where, order: { occurredAt: 'DESC' } });
  }
}
