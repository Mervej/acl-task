import { Reflector } from '@nestjs/core';
import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { PermissionGuard } from './permission.guard';
import { PERMISSION_METADATA_KEY } from './require-permission.decorator';
import { PermissionCheckClient } from '../permission-check-client';

function makeContext(authContext: any, params: Record<string, string>, permission: string, orgUnitParam?: string) {
  const request: any = { authContext, params };
  const context = {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => ({}),
  } as unknown as ExecutionContext;
  return context;
}

describe('PermissionGuard', () => {
  const claims = {
    sub: 'u1', tenantId: 't1', roles: ['manager'],
    permissions: ['expense:approve'], orgUnitId: 'org-1', iat: 0, exp: 0,
  };

  it('allows when the permission client returns true', () => {
    const reflector = { get: jest.fn().mockReturnValue({ permission: 'expense:approve' }) } as unknown as Reflector;
    const permissionClient = new PermissionCheckClient({ accessControlBaseUrl: 'x', serviceApiKey: 'k' });
    const guard = new PermissionGuard(reflector, permissionClient);
    const context = makeContext(claims, {}, 'expense:approve');
    expect(guard.canActivate(context)).toBe(true);
  });

  it('throws ForbiddenException when the permission client returns false', () => {
    const reflector = { get: jest.fn().mockReturnValue({ permission: 'payroll:run' }) } as unknown as Reflector;
    const permissionClient = new PermissionCheckClient({ accessControlBaseUrl: 'x', serviceApiKey: 'k' });
    const guard = new PermissionGuard(reflector, permissionClient);
    const context = makeContext(claims, {}, 'payroll:run');
    expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
  });
});
