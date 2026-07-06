import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { AuthGuard, PermissionGuard, RequirePermission } from '@platform/auth-kit';
import { RolesService } from './roles.service';
import { CreateRoleDto, AssignRoleDto } from './dto';

@Controller()
@UseGuards(AuthGuard, PermissionGuard)
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
