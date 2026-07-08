import { Body, Controller, Headers, Post, UnauthorizedException, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import Redis from 'ioredis';
import { AuthGuard, CurrentAuth, PermissionGuard, PermissionCheckClient, RequirePermission, resolveOwnServiceApiKey } from '@platform/auth-kit';
import { AuditEventEmitter } from '@platform/auth-kit';
import type { AccessTokenClaims } from '@platform/auth-kit';

const auditEmitter = new AuditEventEmitter(new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379'));

const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionCheckClient = new PermissionCheckClient({
  accessControlBaseUrl: process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001',
  serviceApiKey: resolveOwnServiceApiKey('payroll'),
});
const permissionGuard = new PermissionGuard(new Reflector(), permissionCheckClient);

interface RecordReimbursementDto {
  expenseId: string;
  amountCents: number;
}

@Controller('reimbursements')
@UseGuards(authGuard, permissionGuard)
export class ReimbursementsController {
  // tenantId always comes from the caller's own JWT (auth.tenantId), never from
  // the request body — see org-units.controller.ts (access-control) for why.
  @Post()
  @RequirePermission('payroll:run')
  async record(
    @Body() dto: RecordReimbursementDto,
    @CurrentAuth() auth: AccessTokenClaims,
    @Headers('x-service-api-key') serviceApiKey?: string,
  ) {
    if (!serviceApiKey) throw new UnauthorizedException('Missing x-service-api-key header');
    const validKey = await permissionCheckClient.verifyServiceKey(auth.tenantId, serviceApiKey);
    if (!validKey) throw new UnauthorizedException('Invalid service API key');
    await auditEmitter.emit({
      tenantId: auth.tenantId, actorUserId: null, service: 'payroll',
      action: 'payroll.reimbursement.record', resourceType: 'expense', resourceId: dto.expenseId,
      decision: 'allow', viaService: 'expense-management',
    });
    return { status: 'recorded', expenseId: dto.expenseId, amountCents: dto.amountCents };
  }
}
