import { MigrationInterface, QueryRunner } from 'typeorm';

export class Init0001 implements MigrationInterface {
  // TypeORM's MigrationExecutor requires the migration `name` to end in a
  // 13-digit numeric timestamp (it does `parseInt(name.substr(-13))` and
  // throws "migration name is wrong" otherwise, for both CLI and
  // programmatic `runMigrations()` calls). Keeping the readable "Init0001"
  // prefix from the brief and appending a fixed timestamp suffix, matching
  // the workaround used in access-control's control-plane/tenant 0001_init.ts.
  name = 'Init00011704067200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`);
    await queryRunner.query(`
      CREATE TABLE expenses (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        "orgUnitId" UUID,
        "createdByUserId" UUID NOT NULL,
        "amountCents" INTEGER NOT NULL,
        description VARCHAR NOT NULL DEFAULT '',
        status VARCHAR NOT NULL DEFAULT 'pending'
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE expenses`);
  }
}
