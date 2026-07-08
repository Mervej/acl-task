import { Body, Controller, Get, Param, Post, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import Redis from 'ioredis';
import { AuthGuard, CurrentAuth, PermissionGuard, PermissionCheckClient, RequirePermission, resolveOwnServiceApiKey } from '@platform/auth-kit';
import { AuditEventEmitter } from '@platform/auth-kit';
import type { AccessTokenClaims } from '@platform/auth-kit';

const auditEmitter = new AuditEventEmitter(new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379'));

// See packages/access-control/src/org-units/org-units.controller.ts for why guard
// instances (not classes) are passed to @UseGuards() here.
const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionGuard = new PermissionGuard(
  new Reflector(),
  new PermissionCheckClient({
    accessControlBaseUrl: process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001',
    serviceApiKey: resolveOwnServiceApiKey('reporting'),
  }),
);

@Controller()
@UseGuards(authGuard, permissionGuard)
export class ReportsController {
  @Post('report-definitions')
  @RequirePermission('report:create')
  async createDefinition(@Body() body: { name: string }) {
    return { id: 'stub-report-def', ...body };
  }

  @Post('report-definitions/:id/runs')
  @RequirePermission('report:create')
  async runReport(@Param('id') reportDefinitionId: string, @CurrentAuth() auth: AccessTokenClaims) {
    await auditEmitter.emit({
      tenantId: auth.tenantId, actorUserId: auth.sub, service: 'reporting',
      action: 'report.run', resourceType: 'report_run', resourceId: reportDefinitionId, decision: 'allow',
    });
    return { id: 'stub-report-run', reportDefinitionId, status: 'completed', resultSummary: 'No data (stub report engine)' };
  }

  @Get('report-runs/:id')
  @RequirePermission('report:read')
  async getRun(@Param('id') id: string) {
    return { id, status: 'completed', resultSummary: 'No data (stub report engine)' };
  }
}
