import type { Redis } from 'ioredis';
import { Client } from 'pg';
import { TenantConnectionResolver, TenantDbRecord } from '@platform/auth-kit';
import { UserProfile } from './entities';

const SERVICE_NAME = 'user-management';
const CACHE_TTL_SECONDS = 60;

async function fetchRegistryRow(tenantId: string): Promise<TenantDbRecord> {
  const client = new Client({
    host: process.env.DATABASE_HOST ?? 'localhost',
    port: Number(process.env.DATABASE_PORT ?? 5432),
    user: process.env.DATABASE_USER ?? 'postgres',
    password: process.env.DATABASE_PASSWORD ?? 'postgres',
    database: 'control_plane',
  });
  await client.connect();
  try {
    const result = await client.query(
      `SELECT host, port, database, username, password FROM tenant_db_registry WHERE "tenantId" = $1 AND "serviceName" = $2`,
      [tenantId, SERVICE_NAME],
    );
    if (result.rows.length === 0) throw new Error(`No DB registered for tenant ${tenantId}`);
    return result.rows[0] as TenantDbRecord;
  } finally {
    await client.end();
  }
}

export function createTenantDataSourceResolver(redis: Redis): TenantConnectionResolver {
  return new TenantConnectionResolver({
    serviceName: SERVICE_NAME,
    entities: [UserProfile],
    lookupTenantDb: async (tenantId: string): Promise<TenantDbRecord> => {
      const cacheKey = `tenant-db:${SERVICE_NAME}:${tenantId}`;
      const cached = await redis.get(cacheKey);
      if (cached) return JSON.parse(cached) as TenantDbRecord;
      const record = await fetchRegistryRow(tenantId);
      await redis.set(cacheKey, JSON.stringify(record), 'EX', CACHE_TTL_SECONDS);
      return record;
    },
  });
}
