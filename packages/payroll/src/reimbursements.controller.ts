import { Body, Controller, Headers, Post, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthGuard, PermissionGuard, RequirePermission } from '@platform/auth-kit';

interface RecordReimbursementDto {
  tenantId: string;
  expenseId: string;
  amountCents: number;
}

async function verifyServiceKey(tenantId: string, key: string): Promise<boolean> {
  const res = await fetch(`${process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001'}/authz/verify-service-key`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ tenantId, key }),
  });
  if (!res.ok) return false;
  const body = (await res.json()) as { valid: boolean };
  return body.valid;
}

@Controller('reimbursements')
@UseGuards(AuthGuard, PermissionGuard)
export class ReimbursementsController {
  @Post()
  @RequirePermission('payroll:run')
  async record(
    @Body() dto: RecordReimbursementDto,
    @Headers('x-service-api-key') serviceApiKey?: string,
  ) {
    if (!serviceApiKey) throw new UnauthorizedException('Missing x-service-api-key header');
    const validKey = await verifyServiceKey(dto.tenantId, serviceApiKey);
    if (!validKey) throw new UnauthorizedException('Invalid service API key');
    return { status: 'recorded', expenseId: dto.expenseId, amountCents: dto.amountCents };
  }
}
