import { Body, Controller, Get, Headers, NotFoundException, Param, Post, Query, UseGuards } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, CurrentAuth, PermissionGuard, PermissionCheckClient, RequirePermission, resolveOwnServiceApiKey } from '@platform/auth-kit';
import type { AccessTokenClaims } from '@platform/auth-kit';
import { ExpensesService } from './expenses.service';
import { CreateExpenseDto } from './dto';

// See packages/access-control/src/org-units/org-units.controller.ts for why guard
// instances (not classes) are passed to @UseGuards() here.
const authGuard = new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me');
const permissionGuard = new PermissionGuard(
  new Reflector(),
  new PermissionCheckClient({
    accessControlBaseUrl: process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001',
    serviceApiKey: resolveOwnServiceApiKey('expense-management'),
  }),
);

@Controller('expenses')
@UseGuards(authGuard, permissionGuard)
export class ExpensesController {
  constructor(private readonly expensesService: ExpensesService) {}

  // tenantId always comes from the caller's own JWT (auth.tenantId), never from
  // the request body/query — see org-units.controller.ts (access-control) for why.
  @Post()
  @RequirePermission('expense:create')
  async create(@Body() dto: CreateExpenseDto, @CurrentAuth() auth: AccessTokenClaims) {
    return this.expensesService.create(
      auth.tenantId,
      dto.orgUnitId ?? null,
      auth.sub,
      dto.amountCents,
      dto.description ?? '',
    );
  }

  @Get(':id')
  @RequirePermission('expense:read')
  async get(@Param('id') id: string, @CurrentAuth() auth: AccessTokenClaims) {
    const expense = await this.expensesService.get(auth.tenantId, id);
    if (!expense) throw new NotFoundException('Expense not found');
    return expense;
  }

  @Get()
  @RequirePermission('expense:read')
  async list(@CurrentAuth() auth: AccessTokenClaims, @Query('orgUnitId') orgUnitId?: string) {
    return this.expensesService.list(auth.tenantId, orgUnitId);
  }

  @Post(':id/approve')
  @RequirePermission('expense:approve')
  async approve(
    @Param('id') id: string,
    @CurrentAuth() auth: AccessTokenClaims,
    @Headers('authorization') authorizationHeader: string,
  ) {
    return this.expensesService.approve(auth.tenantId, id, authorizationHeader, resolveOwnServiceApiKey('expense-management'));
  }
}
