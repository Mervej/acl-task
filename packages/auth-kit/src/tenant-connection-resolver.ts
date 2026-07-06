import { DataSource } from 'typeorm';

export interface TenantDbRecord {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
}

interface TenantConnectionResolverOptions {
  serviceName: string;
  entities: Function[];
  lookupTenantDb: (tenantId: string) => Promise<TenantDbRecord>;
  maxOpenConnections?: number;
}

export class TenantConnectionResolver {
  private readonly opts: Required<TenantConnectionResolverOptions>;
  private readonly pools = new Map<string, DataSource>();
  private readonly lruOrder: string[] = [];
  private readonly inFlight = new Map<string, Promise<DataSource>>();

  constructor(opts: TenantConnectionResolverOptions) {
    this.opts = { maxOpenConnections: 100, ...opts };
  }

  async getConnection(tenantId: string): Promise<DataSource> {
    const cached = this.pools.get(tenantId);
    if (cached) {
      this.touch(tenantId);
      return cached;
    }

    const pending = this.inFlight.get(tenantId);
    if (pending) {
      return pending;
    }

    const creation = this.createAndCacheConnection(tenantId).finally(() => {
      this.inFlight.delete(tenantId);
    });
    this.inFlight.set(tenantId, creation);
    return creation;
  }

  private async createAndCacheConnection(tenantId: string): Promise<DataSource> {
    const record = await this.opts.lookupTenantDb(tenantId);
    const dataSource = await this.createDataSource(record);
    this.pools.set(tenantId, dataSource);
    this.touch(tenantId);
    this.evictIfNeeded();
    return dataSource;
  }

  protected async createDataSource(record: TenantDbRecord): Promise<DataSource> {
    const dataSource = new DataSource({
      type: 'postgres',
      host: record.host,
      port: record.port,
      database: record.database,
      username: record.username,
      password: record.password,
      entities: this.opts.entities,
      synchronize: false,
    });
    await dataSource.initialize();
    return dataSource;
  }

  private touch(tenantId: string): void {
    const idx = this.lruOrder.indexOf(tenantId);
    if (idx !== -1) this.lruOrder.splice(idx, 1);
    this.lruOrder.push(tenantId);
  }

  private evictIfNeeded(): void {
    while (this.lruOrder.length > this.opts.maxOpenConnections) {
      const oldest = this.lruOrder.shift();
      if (!oldest) break;
      const dataSource = this.pools.get(oldest);
      this.pools.delete(oldest);
      if (dataSource) {
        void dataSource.destroy().catch((err) => {
          console.error(`Failed to destroy connection for tenant ${oldest}:`, err);
        });
      }
    }
  }
}
