import { SetMetadata } from '@nestjs/common';

export const PERMISSION_METADATA_KEY = 'permission_metadata';

export interface PermissionMetadata {
  permission: string;
  orgUnitParam?: string;
}

export const RequirePermission = (permission: string, opts?: { orgUnitParam?: string }) =>
  SetMetadata(PERMISSION_METADATA_KEY, { permission, orgUnitParam: opts?.orgUnitParam });
