import { MigrationInterface, QueryRunner } from 'typeorm';

export class TenantInit0001 implements MigrationInterface {
  // TypeORM's MigrationExecutor requires the migration `name` to end in a
  // 13-digit numeric timestamp (it does `parseInt(name.substr(-13))` and
  // throws "migration name is wrong" otherwise, for both CLI and
  // programmatic `runMigrations()` calls). Keeping the readable
  // "TenantInit0001" prefix from the brief and appending a fixed timestamp
  // suffix, matching the workaround used in control-plane's 0001_init.ts.
  name = 'TenantInit00011704067200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`);
    await queryRunner.query(`
      CREATE TABLE users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        email VARCHAR NOT NULL,
        "passwordHash" VARCHAR NOT NULL,
        status VARCHAR NOT NULL DEFAULT 'active',
        UNIQUE ("tenantId", email)
      )
    `);
    await queryRunner.query(`
      CREATE TABLE org_units (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        name VARCHAR NOT NULL,
        "parentId" UUID
      )
    `);
    await queryRunner.query(`
      CREATE TABLE roles (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        name VARCHAR NOT NULL,
        description VARCHAR NOT NULL DEFAULT '',
        "isSystemRole" BOOLEAN NOT NULL DEFAULT false
      )
    `);
    await queryRunner.query(`
      CREATE TABLE role_permissions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "roleId" UUID NOT NULL,
        "permissionKey" VARCHAR NOT NULL
      )
    `);
    await queryRunner.query(`
      CREATE TABLE role_assignments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        "userId" UUID NOT NULL,
        "roleId" UUID NOT NULL,
        "orgUnitId" UUID
      )
    `);
    await queryRunner.query(`
      CREATE TABLE api_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        "ownerService" VARCHAR NOT NULL,
        "keyHash" VARCHAR NOT NULL,
        "revokedAt" TIMESTAMPTZ
      )
    `);
    await queryRunner.query(`
      CREATE TABLE refresh_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        "userId" UUID NOT NULL,
        "tokenHash" VARCHAR NOT NULL,
        "expiresAt" TIMESTAMPTZ NOT NULL,
        "revokedAt" TIMESTAMPTZ
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE refresh_tokens`);
    await queryRunner.query(`DROP TABLE api_keys`);
    await queryRunner.query(`DROP TABLE role_assignments`);
    await queryRunner.query(`DROP TABLE role_permissions`);
    await queryRunner.query(`DROP TABLE roles`);
    await queryRunner.query(`DROP TABLE org_units`);
    await queryRunner.query(`DROP TABLE users`);
  }
}
