import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { ExpensesController } from './expenses.controller';
import { ExpensesService } from './expenses.service';
import { createTenantDataSourceResolver } from './tenant-datasource';

// AuthGuard/PermissionGuard are constructed directly in expenses.controller.ts
// and passed to @UseGuards() as instances — see org-units.controller.ts (access-control) for why.
@Module({
  controllers: [ExpensesController],
  providers: [
    {
      provide: ExpensesService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        return new ExpensesService(
          createTenantDataSourceResolver(redis),
          process.env.PAYROLL_BASE_URL ?? 'http://localhost:3004',
        );
      },
    },
  ],
})
export class ExpensesModule {}
