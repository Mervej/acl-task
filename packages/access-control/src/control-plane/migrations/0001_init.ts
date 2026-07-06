import { MigrationInterface, QueryRunner } from 'typeorm';

const PERMISSION_KEYS: Array<[string, string]> = [
  ['user:manage', 'Create and manage user profiles'],
  ['expense:create', 'Create an expense record'],
  ['expense:approve', 'Approve an expense record'],
  ['expense:read', 'Read expense records'],
  ['payroll:run', 'Trigger a payroll run'],
  ['payroll:read', 'Read payroll records'],
  ['report:create', 'Create a report definition or run'],
  ['report:read', 'Read reports'],
  ['workflow:create', 'Create a workflow'],
  ['workflow:advance', 'Advance a workflow to its next step'],
  ['notification:send', 'Send a notification'],
  ['notification:read', 'Read notifications'],
  ['invoice:create', 'Create an invoice'],
  ['invoice:read', 'Read invoices'],
  ['role:manage', 'Create and assign roles'],
  ['audit:read', "Read a tenant's audit log"],
];

export class Init0001 implements MigrationInterface {
  // TypeORM's MigrationExecutor requires the migration `name` to end in a
  // 13-digit numeric timestamp (it does `parseInt(name.substr(-13))` and
  // throws "migration name is wrong" otherwise, for both CLI and
  // programmatic `runMigrations()` calls). Keeping the readable "Init0001"
  // prefix from the brief and appending a fixed timestamp suffix.
  name = 'Init00011704067200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`);
    await queryRunner.query(`
      CREATE TABLE tenants (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR NOT NULL,
        slug VARCHAR NOT NULL UNIQUE,
        status VARCHAR NOT NULL DEFAULT 'active'
      )
    `);
    await queryRunner.query(`
      CREATE TABLE tenant_db_registry (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        "serviceName" VARCHAR NOT NULL,
        host VARCHAR NOT NULL,
        port INTEGER NOT NULL,
        database VARCHAR NOT NULL,
        username VARCHAR NOT NULL,
        password VARCHAR NOT NULL,
        UNIQUE ("tenantId", "serviceName")
      )
    `);
    await queryRunner.query(`
      CREATE TABLE permissions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        key VARCHAR NOT NULL UNIQUE,
        description VARCHAR NOT NULL
      )
    `);
    for (const [key, description] of PERMISSION_KEYS) {
      await queryRunner.query(
        `INSERT INTO permissions (key, description) VALUES ($1, $2)`,
        [key, description],
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE permissions`);
    await queryRunner.query(`DROP TABLE tenant_db_registry`);
    await queryRunner.query(`DROP TABLE tenants`);
  }
}
