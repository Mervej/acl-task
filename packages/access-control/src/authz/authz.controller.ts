import { Body, Controller, Post } from '@nestjs/common';
import { AuthzService } from './authz.service';
import { CheckDto, VerifyServiceKeyDto } from './dto';

@Controller('authz')
export class AuthzController {
  constructor(private readonly authzService: AuthzService) {}

  @Post('check')
  async check(@Body() dto: CheckDto) {
    const allowed = await this.authzService.check(
      dto.tenantId,
      dto.userId,
      dto.permission,
      dto.orgUnitId ?? null,
    );
    return { allowed };
  }

  @Post('verify-service-key')
  async verifyServiceKey(@Body() dto: VerifyServiceKeyDto) {
    const valid = await this.authzService.verifyServiceKey(dto.tenantId, dto.key);
    return { valid };
  }
}
