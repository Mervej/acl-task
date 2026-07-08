import { IsInt, IsOptional, IsString, IsUUID, Min } from 'class-validator';

// tenantId and createdByUserId are intentionally not fields here — both are
// derived from the caller's JWT in the controller, never trusted from the
// client (see expenses.controller.ts).
export class CreateExpenseDto {
  @IsOptional() @IsUUID() orgUnitId?: string;
  @IsInt() @Min(1) amountCents!: number;
  @IsOptional() @IsString() description?: string;
}
