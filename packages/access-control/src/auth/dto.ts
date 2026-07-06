import { IsString, MinLength } from 'class-validator';

export class LoginDto {
  @IsString() tenantSlug!: string;
  @IsString() email!: string;
  @IsString() @MinLength(1) password!: string;
}
