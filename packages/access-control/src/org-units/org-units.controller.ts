import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, PermissionGuard, PermissionCheckClient, RequirePermission, CurrentAuth, resolveOwnServiceApiKey } from '@platform/auth-kit';
import type { AccessTokenClaims } from '@platform/auth-kit';
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
    serviceApiKey: resolveOwnServiceApiKey('access-control'),
  }),
);

@Controller('org-units')
@UseGuards(authGuard, permissionGuard)
export class OrgUnitsController {
  constructor(private readonly orgUnitsService: OrgUnitsService) {}

  // tenantId always comes from the caller's own JWT (auth.tenantId), never from
  // the request body/query — a client-supplied tenantId would let a valid user
  // from one tenant read or write another tenant's data just by changing it.
  @Post()
  @RequirePermission('role:manage')
  async create(@Body() dto: CreateOrgUnitDto, @CurrentAuth() auth: AccessTokenClaims) {
    return this.orgUnitsService.create(auth.tenantId, dto.name, dto.parentId ?? null);
  }

  @Get()
  @RequirePermission('role:manage')
  async list(@CurrentAuth() auth: AccessTokenClaims) {
    return this.orgUnitsService.list(auth.tenantId);
  }
}
