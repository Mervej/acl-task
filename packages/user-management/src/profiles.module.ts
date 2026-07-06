import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { Reflector } from '@nestjs/core';
import { ProfilesController } from './profiles.controller';
import { ProfilesService } from './profiles.service';
import { AuthGuard, PermissionGuard, PermissionCheckClient } from '@platform/auth-kit';
import { createTenantDataSourceResolver } from './tenant-datasource';

@Module({
  controllers: [ProfilesController],
  providers: [
    {
      provide: ProfilesService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        return new ProfilesService(
          createTenantDataSourceResolver(redis),
          process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001',
          process.env.SERVICE_API_KEY ?? '',
        );
      },
    },
    { provide: AuthGuard, useFactory: () => new AuthGuard(process.env.JWT_SECRET ?? 'dev-secret-change-me') },
    {
      provide: PermissionGuard,
      useFactory: (reflector: Reflector) =>
        new PermissionGuard(
          reflector,
          new PermissionCheckClient({
            accessControlBaseUrl: process.env.ACCESS_CONTROL_BASE_URL ?? 'http://localhost:3001',
            serviceApiKey: process.env.SERVICE_API_KEY ?? '',
          }),
        ),
      inject: [Reflector],
    },
  ],
})
export class ProfilesModule {}
