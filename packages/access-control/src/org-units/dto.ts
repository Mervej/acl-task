import { IsOptional, IsString, IsUUID } from 'class-validator';

export class CreateOrgUnitDto {
  @IsString() name!: string;
  @IsOptional() @IsUUID() parentId?: string;
}
