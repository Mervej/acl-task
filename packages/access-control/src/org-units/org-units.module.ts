import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { OrgUnitsController } from './org-units.controller';
import { OrgUnitsService } from './org-units.service';
import { createTenantDataSourceResolver } from '../tenant/tenant-datasource';

// AuthGuard/PermissionGuard are constructed directly in org-units.controller.ts
// and passed to @UseGuards() as instances — see the comment there for why.
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
  ],
})
export class OrgUnitsModule {}
