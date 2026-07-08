import { Body, Controller, Get, NotFoundException, Param, Post, Query, UseGuards } from '@nestjs/common';
import { IsArray, IsOptional, IsUUID } from 'class-validator';
import { Reflector } from '@nestjs/core';
import { AuthGuard, CurrentAuth, PermissionGuard, PermissionCheckClient, RequirePermission, resolveOwnServiceApiKey } from '@platform/auth-kit';
import type { AccessTokenClaims } from '@platform/auth-kit';
import { PayrollRunsService } from './payroll-runs.service';

// tenantId/triggeredByUserId are intentionally not fields here — both are
// derived from the caller's JWT in the controller, never trusted from the
// client (see org-units.controller.ts in access-control for why).
class TriggerPayrollRunDto {
  @IsOptional() @IsUUID() orgUnitId?: string;
  @IsArray() employeeUserIds!: string[];
}

// See packages/access-control/src/org-units/org-units.controller.ts for why guard
// instances (not classes) are passed to @UseGuards() here.
const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionGuard = new PermissionGuard(
  new Reflector(),
  new PermissionCheckClient({
    accessControlBaseUrl: process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001',
    serviceApiKey: resolveOwnServiceApiKey('payroll'),
  }),
);

@Controller('payroll-runs')
@UseGuards(authGuard, permissionGuard)
export class PayrollRunsController {
  constructor(private readonly payrollRunsService: PayrollRunsService) {}

  @Post()
  @RequirePermission('payroll:run')
  async trigger(@Body() dto: TriggerPayrollRunDto, @CurrentAuth() auth: AccessTokenClaims) {
    return this.payrollRunsService.trigger(auth.tenantId, dto.orgUnitId ?? null, auth.sub, dto.employeeUserIds);
  }

  @Get(':id')
  @RequirePermission('payroll:read')
  async get(@Param('id') id: string, @CurrentAuth() auth: AccessTokenClaims) {
    const run = await this.payrollRunsService.get(auth.tenantId, id);
    if (!run) throw new NotFoundException('Payroll run not found');
    return run;
  }

  @Get()
  @RequirePermission('payroll:read')
  async list(@CurrentAuth() auth: AccessTokenClaims, @Query('orgUnitId') orgUnitId?: string) {
    return this.payrollRunsService.list(auth.tenantId, orgUnitId);
  }
}
