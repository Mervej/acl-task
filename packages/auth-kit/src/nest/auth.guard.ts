import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { verifyAccessToken, InvalidTokenError } from '../jwt';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly jwtSecret: string) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const header: string | undefined = request.headers['authorization'];
    if (!header?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing bearer token');
    }
    const token = header.slice('Bearer '.length);
    try {
      request.authContext = verifyAccessToken(token, this.jwtSecret);
      return true;
    } catch (err) {
      if (err instanceof InvalidTokenError) {
        throw new UnauthorizedException(err.message);
      }
      throw err;
    }
  }
}
