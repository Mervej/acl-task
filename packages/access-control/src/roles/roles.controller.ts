import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, PermissionGuard, PermissionCheckClient, RequirePermission } from '@platform/auth-kit';
import { RolesService } from './roles.service';
import { CreateRoleDto, AssignRoleDto } from './dto';

// See org-units.controller.ts for why guard instances (not classes) are passed to @UseGuards().
const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionGuard = new PermissionGuard(
  new Reflector(),
  new PermissionCheckClient({
    accessControlBaseUrl: `http://localhost:${process.env.PORT ?? 3001}`,
    serviceApiKey: process.env.ACCESS_CONTROL_SELF_KEY ?? '',
  }),
);

@Controller()
@UseGuards(authGuard, permissionGuard)
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Post('roles')
  @RequirePermission('role:manage')
  async create(@Body() dto: CreateRoleDto) {
    return this.rolesService.createRole(dto.tenantId, dto.name, dto.description ?? '', dto.permissionKeys);
  }

  @Get('roles')
  @RequirePermission('role:manage')
  async list(@Query('tenantId') tenantId: string) {
    return this.rolesService.listRoles(tenantId);
  }

  @Post('role-assignments')
  @RequirePermission('role:manage')
  async assign(@Body() dto: AssignRoleDto) {
    await this.rolesService.assignRole(dto.tenantId, dto.userId, dto.roleId, dto.orgUnitId ?? null);
    return { status: 'assigned' };
  }
}
