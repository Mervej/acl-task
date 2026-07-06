import { DataSource } from 'typeorm';
import { Tenant, TenantDbRegistry, Permission } from './entities';

export const controlPlaneDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DATABASE_HOST ?? 'localhost',
  port: Number(process.env.DATABASE_PORT ?? 5432),
  username: process.env.DATABASE_USER ?? 'postgres',
  password: process.env.DATABASE_PASSWORD ?? 'postgres',
  database: 'control_plane',
  entities: [Tenant, TenantDbRegistry, Permission],
  migrations: ['src/control-plane/migrations/*.ts'],
  synchronize: false,
});
