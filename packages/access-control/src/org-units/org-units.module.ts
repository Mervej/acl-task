import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { OrgUnitsController } from './org-units.controller';
import { OrgUnitsService } from './org-units.service';
import { AuthGuard, PermissionGuard, PermissionCheckClient } from '@platform/auth-kit';
import { createTenantDataSourceResolver } from '../tenant/tenant-datasource';
import { Reflector } from '@nestjs/core';

@Module({
  controllers: [OrgUnitsController],
  providers: [
    {
      provide: OrgUnitsService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        return new OrgUnitsService(createTenantDataSourceResolver(redis));
      },
    },
    { provide: AuthGuard, useFactory: () => new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me') },
    {
      provide: PermissionGuard,
      useFactory: (reflector: Reflector) =>
        new PermissionGuard(
          reflector,
          new PermissionCheckClient({
            accessControlBaseUrl: `http://localhost:${process.env.PORT ?? 3001}`,
            serviceApiKey: process.env.ACCESS_CONTROL_SELF_KEY ?? '',
          }),
        ),
      inject: [Reflector],
    },
  ],
})
export class OrgUnitsModule {}
