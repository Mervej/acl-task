import { Body, Controller, ForbiddenException, Get, NotFoundException, Param, Post, Query, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, CurrentAuth, PermissionGuard, PermissionCheckClient, RequirePermission } from '@platform/auth-kit';
import type { AccessTokenClaims } from '@platform/auth-kit';
import { ProfilesService } from './profiles.service';
import { CreateProfileDto } from './dto';

// See packages/access-control/src/org-units/org-units.controller.ts for why guard
// instances (not classes) are passed to @UseGuards() here.
const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionGuard = new PermissionGuard(
  new Reflector(),
  new PermissionCheckClient({
    accessControlBaseUrl: process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001',
    serviceApiKey: process.env.SERVICE_API_KEY ?? '',
  }),
);

@Controller('profiles')
@UseGuards(authGuard, permissionGuard)
export class ProfilesController {
  constructor(private readonly profilesService: ProfilesService) {}

  @Post()
  @RequirePermission('user:manage')
  async create(@Body() dto: CreateProfileDto) {
    return this.profilesService.createProfile({
      tenantId: dto.tenantId,
      email: dto.email,
      password: dto.password,
      fullName: dto.fullName,
      jobTitle: dto.jobTitle ?? '',
      orgUnitId: dto.orgUnitId ?? null,
      managerId: dto.managerId ?? null,
      hireDate: dto.hireDate,
    });
  }

  // NOTE on org-unit scoping: auth-kit's PermissionGuard resolves `orgUnitParam` from
  // `request.params[orgUnitParam]` — a route *path* segment (see
  // packages/auth-kit/src/nest/permission.guard.ts). This route is `GET /profiles/:id`,
  // which has no `:orgUnitId` path segment, so `{ orgUnitParam: 'orgUnitId' }` as
  // written in the plan would always resolve to `undefined -> null` and silently
  // disable org-unit scoping (PermissionCheckClient.check treats a null target org
  // unit as "always allowed"). The org unit we actually want to scope on is a field of
  // the profile being fetched, which isn't known until after the DB lookup happens in
  // the handler — a guard that runs before the handler can't see it. So we take the
  // plain permission check via the guard, then apply the same org-unit comparison
  // PermissionCheckClient.check performs, by hand, once the record is loaded.
  @Get(':id')
  @RequirePermission('user:manage')
  async get(
    @Param('id') id: string,
    @Query('tenantId') tenantId: string,
    @CurrentAuth() auth: AccessTokenClaims,
  ) {
    const profile = await this.profilesService.getProfile(tenantId, id);
    if (!profile) throw new NotFoundException('Profile not found');
    if (auth.orgUnitId !== null && profile.orgUnitId !== null && auth.orgUnitId !== profile.orgUnitId) {
      throw new ForbiddenException('Missing permission: user:manage');
    }
    return profile;
  }

  @Get()
  @RequirePermission('user:manage')
  async list(@Query('tenantId') tenantId: string, @Query('orgUnitId') orgUnitId?: string) {
    return this.profilesService.listProfiles(tenantId, orgUnitId);
  }
}
