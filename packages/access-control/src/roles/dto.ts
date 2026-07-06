import { ArrayNotEmpty, IsArray, IsOptional, IsString, IsUUID } from 'class-validator';

export class CreateRoleDto {
  @IsUUID() tenantId!: string;
  @IsString() name!: string;
  @IsOptional() @IsString() description?: string;
  @IsArray() @ArrayNotEmpty() permissionKeys!: string[];
}

export class AssignRoleDto {
  @IsUUID() tenantId!: string;
  @IsUUID() userId!: string;
  @IsUUID() roleId!: string;
  @IsOptional() @IsUUID() orgUnitId?: string;
}
