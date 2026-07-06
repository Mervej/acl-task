import { Module } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard, PermissionGuard, PermissionCheckClient } from '@platform/auth-kit';
import { ReimbursementsController } from './reimbursements.controller';

@Module({
  controllers: [ReimbursementsController],
  providers: [
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
export class AppModule {}
