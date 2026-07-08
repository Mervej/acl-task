import { ArrayNotEmpty, IsArray, IsOptional, IsString, IsUUID } from 'class-validator';

export class CreateRoleDto {
  @IsString() name!: string;
  @IsOptional() @IsString() description?: string;
  @IsArray() @ArrayNotEmpty() permissionKeys!: string[];
}

export class AssignRoleDto {
  @IsUUID() userId!: string;
  @IsUUID() roleId!: string;
  @IsOptional() @IsUUID() orgUnitId?: string;
}
