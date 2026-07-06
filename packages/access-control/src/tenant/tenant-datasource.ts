import type { Redis } from 'ioredis';
import { TenantConnectionResolver, TenantDbRecord } from '@platform/auth-kit';
import { controlPlaneDataSource } from '../control-plane/data-source';
import { TenantDbRegistry } from '../control-plane/entities';
import { User, OrgUnit, Role, RolePermission, RoleAssignment } from './entities';

const SERVICE_NAME = 'access-control';
const CACHE_TTL_SECONDS = 60;

export function createTenantDataSourceResolver(redis: Redis): TenantConnectionResolver {
  return new TenantConnectionResolver({
    serviceName: SERVICE_NAME,
    entities: [User, OrgUnit, Role, RolePermission, RoleAssignment],
    lookupTenantDb: async (tenantId: string): Promise<TenantDbRecord> => {
      const cacheKey = `tenant-db:${SERVICE_NAME}:${tenantId}`;
      const cached = await redis.get(cacheKey);
      if (cached) return JSON.parse(cached) as TenantDbRecord;

      const repo = controlPlaneDataSource.getRepository(TenantDbRegistry);
      const record = await repo.findOneOrFail({ where: { tenantId, serviceName: SERVICE_NAME } });
      const dbRecord: TenantDbRecord = {
        host: record.host,
        port: record.port,
        database: record.database,
        username: record.username,
        password: record.password,
      };
      await redis.set(cacheKey, JSON.stringify(dbRecord), 'EX', CACHE_TTL_SECONDS);
      return dbRecord;
    },
  });
}
