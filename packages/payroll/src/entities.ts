import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('payroll_runs')
export class PayrollRun {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column({ type: 'uuid', nullable: true }) orgUnitId!: string | null;
  @Column() triggeredByUserId!: string;
  @Column({ default: 'pending' }) status!: 'pending' | 'completed';
  @Column({ default: 0 }) totalAmountCents!: number;
}

@Entity('payslips')
export class Payslip {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column() payrollRunId!: string;
  @Column() employeeUserId!: string;
  @Column() amountCents!: number;
}
