import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, PermissionGuard, PermissionCheckClient, RequirePermission, CurrentAuth } from '@platform/auth-kit';
import { OrgUnitsService } from './org-units.service';
import { CreateOrgUnitDto } from './dto';

// NestJS's @UseGuards(ClassRef) auto-instantiates the guard via its own
// constructor reflection; it does not reuse a same-token custom provider
// registered elsewhere in the module. AuthGuard/PermissionGuard take plain
// config values (not injectable tokens), so passing pre-built instances
// here is the working alternative to the module's-provider approach.
const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionGuard = new PermissionGuard(
  new Reflector(),
  new PermissionCheckClient({
    accessControlBaseUrl: `http://localhost:${process.env.PORT ?? 3001}`,
    serviceApiKey: process.env.ACCESS_CONTROL_SELF_KEY ?? '',
  }),
);

@Controller('org-units')
@UseGuards(authGuard, permissionGuard)
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
