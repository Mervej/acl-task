import { Injectable } from '@nestjs/common';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { User, ApiKey } from '../tenant/entities';
import { hashPassword, hashSecret } from '../password';

@Injectable()
export class UsersService {
  constructor(private readonly resolver: TenantConnectionResolver) {}

  async createUser(
    tenantId: string,
    email: string,
    password: string,
  ): Promise<{ id: string; email: string }> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const repo = dataSource.getRepository(User);
    const passwordHash = await hashPassword(password);
    const entity = repo.create({ tenantId, email, passwordHash, status: 'active' });
    const saved = await repo.save(entity);
    return { id: saved.id, email: saved.email };
  }

  async getUser(
    tenantId: string,
    userId: string,
  ): Promise<{ id: string; email: string; status: string } | null> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const repo = dataSource.getRepository(User);
    const found = await repo.findOne({ where: { id: userId } });
    if (!found) return null;
    return { id: found.id, email: found.email, status: found.status };
  }

  async verifyServiceApiKey(tenantId: string, plainKey: string): Promise<boolean> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const repo = dataSource.getRepository(ApiKey);
    const keyHash = hashSecret(plainKey);
    const found = await repo.findOne({ where: { tenantId, keyHash, revokedAt: undefined as never } });
    return !!found && found.keyHash === keyHash && !found.revokedAt;
  }
}
