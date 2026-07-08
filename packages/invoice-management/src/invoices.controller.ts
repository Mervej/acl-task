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
    serviceApiKey: resolveOwnServiceApiKey('invoice-management'),
  }),
);

@Controller('invoices')
@UseGuards(authGuard, permissionGuard)
export class InvoiceController {
  @Post()
  @RequirePermission('invoice:create')
  async create(@Body() body: { totalAmountCents: number }, @CurrentAuth() auth: AccessTokenClaims) {
    await auditEmitter.emit({
      tenantId: auth.tenantId, actorUserId: auth.sub, service: 'invoice-management',
      action: 'invoice.create', resourceType: 'invoice', resourceId: null, decision: 'allow',
    });
    return { id: 'stub-invoice', ...body, status: 'draft' };
  }

  @Get(':id')
  @RequirePermission('invoice:read')
  async get(@Param('id') id: string) {
    return { id, status: 'draft', totalAmountCents: 0 };
  }

  @Get()
  @RequirePermission('invoice:read')
  async list() {
    return [];
  }
}
