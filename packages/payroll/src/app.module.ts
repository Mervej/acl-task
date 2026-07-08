import { Module } from '@nestjs/common';
import { ReimbursementsController } from './reimbursements.controller';
import { PayrollRunsModule } from './payroll-runs.module';

// AuthGuard/PermissionGuard are constructed directly in reimbursements.controller.ts
// and payroll-runs.controller.ts, and passed to @UseGuards() as instances — see
// org-units.controller.ts (access-control) for why.
@Module({
  imports: [PayrollRunsModule],
  controllers: [ReimbursementsController],
})
export class AppModule {}
