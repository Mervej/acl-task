import { Injectable } from '@nestjs/common';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { AuthService } from '../auth/auth.service';
import { UsersService } from '../users/users.service';
import { OrgUnit } from '../tenant/entities';

@Injectable()
export class AuthzService {
  constructor(
    private readonly resolver: TenantConnectionResolver,
    private readonly authService: AuthService,
    private readonly usersService: UsersService,
  ) {}

  async check(
    tenantId: string,
    userId: string,
    permission: string,
    orgUnitId: string | null,
  ): Promise<boolean> {
    const effective = await this.authService.resolveEffectivePermissions(tenantId, userId);
    if (!effective.permissions.includes(permission)) return false;
    if (orgUnitId === null || effective.orgUnitId === null) return true;
    if (effective.orgUnitId === orgUnitId) return true;

    const dataSource = await this.resolver.getConnection(tenantId);
    const orgUnits = await dataSource.getRepository(OrgUnit).find({ where: { tenantId } });
    return this.isDescendant(orgUnits, effective.orgUnitId, orgUnitId);
  }

  async verifyServiceKey(tenantId: string, plainKey: string): Promise<boolean> {
    return this.usersService.verifyServiceApiKey(tenantId, 'unspecified', plainKey);
  }

  private isDescendant(
    orgUnits: Array<{ id: string; parentId: string | null }>,
    ancestorId: string,
    targetId: string,
  ): boolean {
    const parentOf = new Map(orgUnits.map((u) => [u.id, u.parentId]));
    let current: string | null | undefined = targetId;
    while (current) {
      if (current === ancestorId) return true;
      current = parentOf.get(current) ?? null;
    }
    return false;
  }
}
