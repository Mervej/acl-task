import type { Redis } from 'ioredis';
import { Client } from 'pg';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { consumeTenantStream } from './consumer';

async function fetchActiveTenantIds(): Promise<string[]> {
  const client = new Client({
    host: process.env.DATABASE_HOST ?? 'localhost',
    port: Number(process.env.DATABASE_PORT ?? 5432),
    user: process.env.DATABASE_USER ?? 'postgres',
    password: process.env.DATABASE_PASSWORD ?? 'postgres',
    database: 'control_plane',
  });
  await client.connect();
  try {
    const result = await client.query(`SELECT id FROM tenants WHERE status = 'active'`);
    return result.rows.map((row) => row.id as string);
  } finally {
    await client.end();
  }
}

// One consumer poll pass across every active tenant, sequentially — simpler
// than a per-tenant background timer, sufficient for a handful of demo
// tenants. A real deployment would shard tenants across consumer processes
// rather than one process polling every tenant in sequence.
export async function consumeAllTenants(
  redis: Redis,
  resolver: TenantConnectionResolver,
  consumerGroup: string,
  consumerName: string,
): Promise<void> {
  const tenantIds = await fetchActiveTenantIds();
  for (const tenantId of tenantIds) {
    await consumeTenantStream(redis, resolver, tenantId, consumerGroup, consumerName).catch((err) => {
      console.error(`Audit consumer error for tenant ${tenantId}:`, err);
    });
  }
}
