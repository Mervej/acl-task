import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, CurrentAuth, PermissionGuard, PermissionCheckClient, RequirePermission, resolveOwnServiceApiKey } from '@platform/auth-kit';
import type { AccessTokenClaims } from '@platform/auth-kit';
import { AuditEventsService } from './audit-events.service';

// See packages/access-control/src/org-units/org-units.controller.ts for why guard
// instances (not classes) are passed to @UseGuards() here.
const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionGuard = new PermissionGuard(
  new Reflector(),
  new PermissionCheckClient({
    accessControlBaseUrl: process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001',
    serviceApiKey: resolveOwnServiceApiKey('audit'),
  }),
);

@Controller('audit-events')
@UseGuards(authGuard, permissionGuard)
export class AuditEventsController {
  constructor(private readonly auditEventsService: AuditEventsService) {}

  // tenantId always comes from the caller's own JWT (auth.tenantId), never from
  // the request query — see org-units.controller.ts (access-control) for why.
  @Get()
  @RequirePermission('audit:read')
  async list(
    @CurrentAuth() auth: AccessTokenClaims,
    @Query('service') service?: string,
    @Query('decision') decision?: 'allow' | 'deny',
  ) {
    return this.auditEventsService.list(auth.tenantId, { service, decision });
  }
}
