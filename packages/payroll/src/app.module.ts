import { Module } from '@nestjs/common';
import { ReimbursementsController } from './reimbursements.controller';

// AuthGuard/PermissionGuard are constructed directly in reimbursements.controller.ts
// and passed to @UseGuards() as instances — see org-units.controller.ts (access-control) for why.
@Module({
  controllers: [ReimbursementsController],
})
export class AppModule {}
