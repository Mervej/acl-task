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
  // A Map's insertion order doubles as LRU order: re-inserting a key on
  // access (delete then set) moves it to the end, so the first key is
  // always the least recently used.
  private readonly pools = new Map<string, DataSource>();
  private readonly inFlight = new Map<string, Promise<DataSource>>();

  constructor(opts: TenantConnectionResolverOptions) {
    this.opts = { maxOpenConnections: 100, ...opts };
  }

  async getConnection(tenantId: string): Promise<DataSource> {
    const cached = this.pools.get(tenantId);
    if (cached) {
      this.pools.delete(tenantId);
      this.pools.set(tenantId, cached);
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

  private evictIfNeeded(): void {
    if (this.pools.size <= this.opts.maxOpenConnections) return;
    const oldestTenantId = this.pools.keys().next().value as string;
    const dataSource = this.pools.get(oldestTenantId);
    this.pools.delete(oldestTenantId);
    void dataSource?.destroy().catch((err) => {
      console.error(`Failed to destroy connection for tenant ${oldestTenantId}:`, err);
    });
  }
}
