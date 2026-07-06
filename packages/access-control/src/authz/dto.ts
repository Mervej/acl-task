import { IsOptional, IsString, IsUUID } from 'class-validator';

export class CheckDto {
  @IsUUID() tenantId!: string;
  @IsUUID() userId!: string;
  @IsString() permission!: string;
  @IsOptional() @IsUUID() orgUnitId?: string;
}

export class VerifyServiceKeyDto {
  @IsUUID() tenantId!: string;
  @IsString() key!: string;
}
