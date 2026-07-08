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
    serviceApiKey: resolveOwnServiceApiKey('workflow'),
  }),
);

@Controller('workflow-instances')
@UseGuards(authGuard, permissionGuard)
export class WorkflowController {
  @Post()
  @RequirePermission('workflow:create')
  async create(@Body() body: { workflowDefinitionId: string }) {
    return { id: 'stub-workflow-instance', ...body, currentStep: 0, status: 'in_progress' };
  }

  @Post(':id/advance')
  @RequirePermission('workflow:advance')
  async advance(@Param('id') id: string, @CurrentAuth() auth: AccessTokenClaims) {
    await auditEmitter.emit({
      tenantId: auth.tenantId, actorUserId: auth.sub, service: 'workflow',
      action: 'workflow.advance', resourceType: 'workflow_instance', resourceId: id,
      decision: 'allow', metadata: { status: 'in_progress', currentStep: 1 },
    });
    return { id, currentStep: 1, status: 'in_progress' };
  }

  @Get(':id')
  @RequirePermission('workflow:create')
  async get(@Param('id') id: string) {
    return { id, currentStep: 0, status: 'in_progress' };
  }
}
