import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { ProfilesController } from './profiles.controller';
import { ProfilesService } from './profiles.service';
import { createTenantDataSourceResolver } from './tenant-datasource';

// AuthGuard/PermissionGuard are constructed directly in profiles.controller.ts
// and passed to @UseGuards() as instances — see org-units.controller.ts for why.
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
  ],
})
export class ProfilesModule {}
