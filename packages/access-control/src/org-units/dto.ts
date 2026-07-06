import { IsOptional, IsString, IsUUID } from 'class-validator';

export class CreateOrgUnitDto {
  @IsUUID() tenantId!: string;
  @IsString() name!: string;
  @IsOptional() @IsUUID() parentId?: string;
}
