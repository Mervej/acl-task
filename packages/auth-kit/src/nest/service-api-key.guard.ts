import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class ServiceApiKeyGuard implements CanActivate {
  constructor(private readonly verifyServiceKey: (key: string) => Promise<boolean>) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const key: string | undefined = request.headers['x-service-api-key'];
    if (!key) throw new UnauthorizedException('Missing x-service-api-key header');
    const valid = await this.verifyServiceKey(key);
    if (!valid) throw new UnauthorizedException('Invalid service API key');
    return true;
  }
}
