import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionCheckClient } from '../permission-check-client';
import { PERMISSION_METADATA_KEY, PermissionMetadata } from './require-permission.decorator';

@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly permissionClient: PermissionCheckClient,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const metadata = this.reflector.get<PermissionMetadata>(
      PERMISSION_METADATA_KEY,
      context.getHandler(),
    );
    if (!metadata) return true;

    const request = context.switchToHttp().getRequest();
    const targetOrgUnitId = metadata.orgUnitParam
      ? request.params[metadata.orgUnitParam] ?? null
      : null;

    const allowed = this.permissionClient.check(
      request.authContext,
      metadata.permission,
      targetOrgUnitId,
    );
    if (!allowed) {
      throw new ForbiddenException(`Missing permission: ${metadata.permission}`);
    }
    return true;
  }
}
