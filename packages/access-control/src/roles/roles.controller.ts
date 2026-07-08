import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, CurrentAuth, PermissionGuard, PermissionCheckClient, RequirePermission, resolveOwnServiceApiKey } from '@platform/auth-kit';
import type { AccessTokenClaims } from '@platform/auth-kit';
import { RolesService } from './roles.service';
import { CreateRoleDto, AssignRoleDto } from './dto';

// See org-units.controller.ts for why guard instances (not classes) are passed to @UseGuards().
const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionGuard = new PermissionGuard(
  new Reflector(),
  new PermissionCheckClient({
    accessControlBaseUrl: `http://localhost:${process.env.PORT ?? 3001}`,
    serviceApiKey: resolveOwnServiceApiKey('access-control'),
  }),
);

@Controller()
@UseGuards(authGuard, permissionGuard)
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  // tenantId always comes from the caller's own JWT (auth.tenantId), never from
  // the request body/query — see org-units.controller.ts for why.
  @Post('roles')
  @RequirePermission('role:manage')
  async create(@Body() dto: CreateRoleDto, @CurrentAuth() auth: AccessTokenClaims) {
    return this.rolesService.createRole(auth.tenantId, dto.name, dto.description ?? '', dto.permissionKeys);
  }

  @Get('roles')
  @RequirePermission('role:manage')
  async list(@CurrentAuth() auth: AccessTokenClaims) {
    return this.rolesService.listRoles(auth.tenantId);
  }

  @Post('role-assignments')
  @RequirePermission('role:manage')
  async assign(@Body() dto: AssignRoleDto, @CurrentAuth() auth: AccessTokenClaims) {
    await this.rolesService.assignRole(auth.tenantId, dto.userId, dto.roleId, dto.orgUnitId ?? null);
    return { status: 'assigned' };
  }
}
