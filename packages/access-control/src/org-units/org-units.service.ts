import { Injectable } from '@nestjs/common';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { OrgUnit } from '../tenant/entities';

@Injectable()
export class OrgUnitsService {
  constructor(private readonly resolver: TenantConnectionResolver) {}

  async create(tenantId: string, name: string, parentId: string | null): Promise<OrgUnit> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const repo = dataSource.getRepository(OrgUnit);
    return repo.save(repo.create({ tenantId, name, parentId }));
  }

  async list(tenantId: string): Promise<OrgUnit[]> {
    const dataSource = await this.resolver.getConnection(tenantId);
    return dataSource.getRepository(OrgUnit).find({ where: { tenantId } });
  }
}
