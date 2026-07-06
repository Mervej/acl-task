import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { AuthzModule } from './authz/authz.module';
import { OrgUnitsModule } from './org-units/org-units.module';

@Module({ imports: [UsersModule, AuthModule, AuthzModule, OrgUnitsModule] })
export class AppModule {}
