import { MigrationInterface, QueryRunner } from 'typeorm';

export class Init0001 implements MigrationInterface {
  // TypeORM parses the last 13 chars of this name as a timestamp — a plain
  // 'Init0001' throws NaN and runMigrations() fails (same fix as every other
  // service's initial migration in this repo).
  name = 'Init00011704067200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`);
    await queryRunner.query(`
      CREATE TABLE payroll_runs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        "orgUnitId" UUID,
        "triggeredByUserId" UUID NOT NULL,
        status VARCHAR NOT NULL DEFAULT 'pending',
        "totalAmountCents" INTEGER NOT NULL DEFAULT 0
      )
    `);
    await queryRunner.query(`
      CREATE TABLE payslips (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "tenantId" UUID NOT NULL,
        "payrollRunId" UUID NOT NULL,
        "employeeUserId" UUID NOT NULL,
        "amountCents" INTEGER NOT NULL
      )
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE payslips`);
    await queryRunner.query(`DROP TABLE payroll_runs`);
  }
}
