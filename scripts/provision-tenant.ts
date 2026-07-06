import { randomBytes } from 'crypto';
import { Client } from 'pg';
import { DataSource } from 'typeorm';
import { controlPlaneDataSource } from '../packages/access-control/src/control-plane/data-source';
import { Tenant, TenantDbRegistry } from '../packages/access-control/src/control-plane/entities';
import {
  User, OrgUnit, Role, RolePermission, RoleAssignment, ApiKey, RefreshToken,
} from '../packages/access-control/src/tenant/entities';
import { hashSecret } from '../packages/access-control/src/password';
import { UserProfile } from '../packages/user-management/src/entities';
import { Expense } from '../packages/expense-management/src/entities';

export interface ServiceDbSpec {
  serviceName: string;
  entities: Function[];
  migrationsGlob: string;
}

export const PROVISIONED_SERVICES: ServiceDbSpec[] = [
  {
    serviceName: 'access-control',
    entities: [User, OrgUnit, Role, RolePermission, RoleAssignment, ApiKey, RefreshToken],
    migrationsGlob: 'packages/access-control/src/tenant/migrations/*.ts',
  },
  {
    serviceName: 'user-management',
    entities: [UserProfile],
    migrationsGlob: 'packages/user-management/src/migrations/*.ts',
  },
  {
    serviceName: 'expense-management',
    entities: [Expense],
    migrationsGlob: 'packages/expense-management/src/migrations/*.ts',
  },
];

const DB_HOST = process.env.DATABASE_HOST ?? 'localhost';
const DB_PORT = Number(process.env.DATABASE_PORT ?? 5432);
const DB_USER = process.env.DATABASE_USER ?? 'postgres';
const DB_PASSWORD = process.env.DATABASE_PASSWORD ?? 'postgres';

async function createDatabaseIfNotExists(databaseName: string): Promise<void> {
  const admin = new Client({ host: DB_HOST, port: DB_PORT, user: DB_USER, password: DB_PASSWORD, database: 'postgres' });
  await admin.connect();
  try {
    const exists = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [databaseName]);
    if (exists.rowCount === 0) {
      await admin.query(`CREATE DATABASE ${databaseName}`);
    }
  } finally {
    await admin.end();
  }
}

export async function provisionTenant(
  slug: string,
  name: string,
): Promise<{ tenantId: string; serviceApiKey: string }> {
  if (!controlPlaneDataSource.isInitialized) await controlPlaneDataSource.initialize();

  const tenantRepo = controlPlaneDataSource.getRepository(Tenant);
  const tenant = await tenantRepo.save(tenantRepo.create({ name, slug, status: 'active' }));

  const registryRepo = controlPlaneDataSource.getRepository(TenantDbRegistry);
  const serviceApiKey = randomBytes(32).toString('hex');

  for (const spec of PROVISIONED_SERVICES) {
    const databaseName = `${spec.serviceName}_${slug}`.replace(/-/g, '_');
    await createDatabaseIfNotExists(databaseName);

    await registryRepo.save(
      registryRepo.create({
        tenantId: tenant.id,
        serviceName: spec.serviceName,
        host: DB_HOST,
        port: DB_PORT,
        database: databaseName,
        username: DB_USER,
        password: DB_PASSWORD,
      }),
    );

    const migrationDataSource = new DataSource({
      type: 'postgres',
      host: DB_HOST,
      port: DB_PORT,
      username: DB_USER,
      password: DB_PASSWORD,
      database: databaseName,
      entities: spec.entities,
      migrations: [spec.migrationsGlob],
      synchronize: false,
    });
    await migrationDataSource.initialize();
    await migrationDataSource.runMigrations();

    if (spec.serviceName === 'access-control') {
      const apiKeyRepo = migrationDataSource.getRepository(ApiKey);
      await apiKeyRepo.save(
        apiKeyRepo.create({
          tenantId: tenant.id,
          ownerService: 'shared',
          keyHash: hashSecret(serviceApiKey),
          revokedAt: null,
        }),
      );
    }

    await migrationDataSource.destroy();
  }

  return { tenantId: tenant.id, serviceApiKey };
}
