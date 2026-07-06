import { Injectable } from '@nestjs/common';
import { In } from 'typeorm';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { Role, RolePermission, RoleAssignment } from '../tenant/entities';

@Injectable()
export class RolesService {
  constructor(private readonly resolver: TenantConnectionResolver) {}

  async createRole(
    tenantId: string,
    name: string,
    description: string,
    permissionKeys: string[],
    isSystemRole = false,
  ): Promise<{ id: string; name: string; permissionKeys: string[] }> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const roleRepo = dataSource.getRepository(Role);
    const role = await roleRepo.save(roleRepo.create({ tenantId, name, description, isSystemRole }));

    const rolePermissionRepo = dataSource.getRepository(RolePermission);
    const rolePermissions = permissionKeys.map((permissionKey) =>
      rolePermissionRepo.create({ roleId: role.id, permissionKey }),
    );
    await rolePermissionRepo.save(rolePermissions);

    return { id: role.id, name: role.name, permissionKeys };
  }

  async listRoles(
    tenantId: string,
  ): Promise<Array<{ id: string; name: string; permissionKeys: string[] }>> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const roles = await dataSource.getRepository(Role).find({ where: { tenantId } });
    const roleIds = roles.map((r) => r.id);
    const rolePermissions = roleIds.length
      ? await dataSource.getRepository(RolePermission).find({ where: { roleId: In(roleIds) } })
      : [];

    return roles.map((role) => ({
      id: role.id,
      name: role.name,
      permissionKeys: rolePermissions
        .filter((rp) => rp.roleId === role.id)
        .map((rp) => rp.permissionKey),
    }));
  }

  async assignRole(
    tenantId: string,
    userId: string,
    roleId: string,
    orgUnitId: string | null,
  ): Promise<void> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const repo = dataSource.getRepository(RoleAssignment);
    await repo.save(repo.create({ tenantId, userId, roleId, orgUnitId }));
  }
}
