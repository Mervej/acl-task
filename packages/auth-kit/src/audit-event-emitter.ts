import type { Redis } from 'ioredis';

export interface AuditEvent {
  tenantId: string;
  actorUserId: string | null;
  service: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  decision: 'allow' | 'deny';
  viaService?: string;
  metadata?: Record<string, unknown>;
}

export class AuditEventEmitter {
  constructor(private readonly redis: Redis) {}

  async emit(event: AuditEvent): Promise<void> {
    const payload = JSON.stringify({ ...event, timestamp: new Date().toISOString() });
    await this.redis.xadd(`audit:${event.tenantId}`, '*', 'payload', payload);
  }
}
