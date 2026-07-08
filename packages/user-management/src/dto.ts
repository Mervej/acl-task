import { IsDateString, IsEmail, IsOptional, IsString, IsUUID, MinLength } from 'class-validator';

export class CreateProfileDto {
  @IsEmail() email!: string;
  @IsString() @MinLength(8) password!: string;
  @IsString() fullName!: string;
  @IsOptional() @IsString() jobTitle?: string;
  @IsOptional() @IsUUID() orgUnitId?: string;
  @IsOptional() @IsUUID() managerId?: string;
  @IsDateString() hireDate!: string;
}
