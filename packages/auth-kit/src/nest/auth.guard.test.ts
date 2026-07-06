import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from './auth.guard';
import { signAccessToken } from '../jwt';

function makeContext(headers: Record<string, string>): ExecutionContext {
  const request: any = { headers };
  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as ExecutionContext;
}

describe('AuthGuard', () => {
  const secret = 'test-secret';
  const guard = new AuthGuard(secret);

  it('attaches authContext for a valid bearer token', () => {
    const token = signAccessToken(
      { sub: 'u1', tenantId: 't1', roles: [], permissions: [], orgUnitId: null },
      secret,
      900,
    );
    const context = makeContext({ authorization: `Bearer ${token}` });
    expect(guard.canActivate(context)).toBe(true);
    const request = context.switchToHttp().getRequest();
    expect(request.authContext.sub).toBe('u1');
  });

  it('throws UnauthorizedException when the header is missing', () => {
    const context = makeContext({});
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });

  it('throws UnauthorizedException for an invalid token', () => {
    const context = makeContext({ authorization: 'Bearer not-a-real-token' });
    expect(() => guard.canActivate(context)).toThrow(UnauthorizedException);
  });
});
