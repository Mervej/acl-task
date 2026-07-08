import type { Redis } from 'ioredis';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { AuditEventRecord } from './entities';

interface AuditPayload {
  tenantId: string;
  actorUserId: string | null;
  service: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  decision: 'allow' | 'deny';
  viaService?: string;
  metadata?: Record<string, unknown>;
  timestamp: string;
}

export async function processStreamMessage(
  resolver: TenantConnectionResolver,
  tenantId: string,
  payloadJson: string,
): Promise<void> {
  const payload = JSON.parse(payloadJson) as AuditPayload;
  const dataSource = await resolver.getConnection(tenantId);
  const repo = dataSource.getRepository(AuditEventRecord);
  await repo.save(
    repo.create({
      tenantId: payload.tenantId,
      actorUserId: payload.actorUserId,
      service: payload.service,
      action: payload.action,
      resourceType: payload.resourceType,
      resourceId: payload.resourceId,
      decision: payload.decision,
      viaService: payload.viaService ?? null,
      metadata: payload.metadata ? JSON.stringify(payload.metadata) : null,
      occurredAt: new Date(payload.timestamp),
    }),
  );
}

export async function consumeTenantStream(
  redis: Redis,
  resolver: TenantConnectionResolver,
  tenantId: string,
  consumerGroup: string,
  consumerName: string,
): Promise<void> {
  const streamKey = `audit:${tenantId}`;
  await redis
    .xgroup('CREATE', streamKey, consumerGroup, '0', 'MKSTREAM')
    .catch(() => undefined); // group may already exist

  const result = await redis.xreadgroup(
    'GROUP', consumerGroup, consumerName,
    'COUNT', 10, 'BLOCK', 5000,
    'STREAMS', streamKey, '>',
  );
  if (!result) return;

  for (const [, entries] of result as Array<[string, Array<[string, string[]]>]>) {
    for (const [entryId, fields] of entries) {
      const payloadIndex = fields.indexOf('payload');
      const payloadJson = fields[payloadIndex + 1];
      await processStreamMessage(resolver, tenantId, payloadJson);
      await redis.xack(streamKey, consumerGroup, entryId);
    }
  }
}
