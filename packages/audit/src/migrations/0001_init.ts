import { MigrationInterface, QueryRunner } from 'typeorm';

export class Init0001 implements MigrationInterface {
  // TypeORM parses the last 13 chars of this name as a timestamp — a plain
  // 'Init0001' throws NaN and runMigrations() fails (same fix as every other
  // service's initial migration in this repo).
  name = 'Init00011704067200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`);
    await queryRunner.query(`
      CREATE TABLE audit_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        "actorUserId" UUID,
        service VARCHAR NOT NULL,
        action VARCHAR NOT NULL,
        "resourceType" VARCHAR NOT NULL,
        "resourceId" VARCHAR,
        decision VARCHAR NOT NULL,
        "viaService" VARCHAR,
        metadata TEXT,
        "occurredAt" TIMESTAMPTZ NOT NULL
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE audit_events`);
  }
}
