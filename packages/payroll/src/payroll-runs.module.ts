import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { PayrollRunsController } from './payroll-runs.controller';
import { PayrollRunsService } from './payroll-runs.service';
import { createTenantDataSourceResolver } from './tenant-datasource';

// AuthGuard/PermissionGuard are constructed directly in payroll-runs.controller.ts
// and passed to @UseGuards() as instances — see org-units.controller.ts (access-control) for why.
@Module({
  controllers: [PayrollRunsController],
  providers: [
    {
      provide: PayrollRunsService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        return new PayrollRunsService(createTenantDataSourceResolver(redis));
      },
    },
  ],
})
export class PayrollRunsModule {}
