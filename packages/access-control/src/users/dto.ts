import { IsEmail, IsString, IsUUID, MinLength } from 'class-validator';

export class CreateUserDto {
  @IsUUID() tenantId!: string;
  @IsEmail() email!: string;
  @IsString() @MinLength(8) password!: string;
}
