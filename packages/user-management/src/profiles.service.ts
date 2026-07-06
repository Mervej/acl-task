import { Injectable } from '@nestjs/common';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { UserProfile } from './entities';

interface CreateProfileInput {
  tenantId: string;
  email: string;
  password: string;
  fullName: string;
  jobTitle: string;
  orgUnitId: string | null;
  managerId: string | null;
  hireDate: string;
}

@Injectable()
export class ProfilesService {
  constructor(
    private readonly resolver: TenantConnectionResolver,
    private readonly accessControlBaseUrl: string,
    private readonly serviceApiKey: string,
  ) {}

  async createProfile(input: CreateProfileInput): Promise<UserProfile> {
    const res = await fetch(`${this.accessControlBaseUrl}/internal/users`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-service-api-key': this.serviceApiKey },
      body: JSON.stringify({ tenantId: input.tenantId, email: input.email, password: input.password }),
    });
    if (!res.ok) throw new Error(`Failed to provision identity: ${res.status}`);
    const identity = (await res.json()) as { id: string };

    const dataSource = await this.resolver.getConnection(input.tenantId);
    const repo = dataSource.getRepository(UserProfile);
    const profile = repo.create({
      tenantId: input.tenantId,
      userId: identity.id,
      fullName: input.fullName,
      jobTitle: input.jobTitle,
      orgUnitId: input.orgUnitId,
      managerId: input.managerId,
      hireDate: input.hireDate,
    });
    return repo.save(profile);
  }

  async getProfile(tenantId: string, id: string): Promise<UserProfile | null> {
    const dataSource = await this.resolver.getConnection(tenantId);
    return dataSource.getRepository(UserProfile).findOne({ where: { id, tenantId } });
  }

  async listProfiles(tenantId: string, orgUnitId?: string): Promise<UserProfile[]> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const where: Record<string, unknown> = { tenantId };
    if (orgUnitId) where.orgUnitId = orgUnitId;
    return dataSource.getRepository(UserProfile).find({ where });
  }
}
