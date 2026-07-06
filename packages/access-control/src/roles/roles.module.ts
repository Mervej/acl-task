import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { Reflector } from '@nestjs/core';
import { RolesController } from './roles.controller';
import { RolesService } from './roles.service';
import { AuthGuard, PermissionGuard, PermissionCheckClient } from '@platform/auth-kit';
import { createTenantDataSourceResolver } from '../tenant/tenant-datasource';

@Module({
  controllers: [RolesController],
  providers: [
    {
      provide: RolesService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        return new RolesService(createTenantDataSourceResolver(redis));
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
export class RolesModule {}
