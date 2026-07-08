import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { AuditEventsController } from './audit-events.controller';
import { AuditEventsService } from './audit-events.service';
import { createTenantDataSourceResolver } from './tenant-datasource';

// AuthGuard/PermissionGuard are constructed directly in audit-events.controller.ts
// and passed to @UseGuards() as instances — see org-units.controller.ts (access-control) for why.
@Module({
  controllers: [AuditEventsController],
  providers: [
    {
      provide: AuditEventsService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        return new AuditEventsService(createTenantDataSourceResolver(redis));
      },
    },
  ],
})
export class AppModule {}
