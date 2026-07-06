import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { AuthGuard, PermissionGuard, RequirePermission, CurrentAuth } from '@platform/auth-kit';
import { OrgUnitsService } from './org-units.service';
import { CreateOrgUnitDto } from './dto';

@Controller('org-units')
@UseGuards(AuthGuard, PermissionGuard)
export class OrgUnitsController {
  constructor(private readonly orgUnitsService: OrgUnitsService) {}

  @Post()
  @RequirePermission('role:manage')
  async create(@Body() dto: CreateOrgUnitDto) {
    return this.orgUnitsService.create(dto.tenantId, dto.name, dto.parentId ?? null);
  }

  @Get()
  @RequirePermission('role:manage')
  async list(@Query('tenantId') tenantId: string, @CurrentAuth() _auth: unknown) {
    return this.orgUnitsService.list(tenantId);
  }
}
