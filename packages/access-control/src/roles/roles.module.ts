import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { RolesController } from './roles.controller';
import { RolesService } from './roles.service';
import { createTenantDataSourceResolver } from '../tenant/tenant-datasource';

// AuthGuard/PermissionGuard are constructed directly in roles.controller.ts
// and passed to @UseGuards() as instances — see org-units.controller.ts for why.
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
  ],
})
export class RolesModule {}
