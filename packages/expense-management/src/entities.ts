import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('expenses')
export class Expense {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column({ type: 'uuid', nullable: true }) orgUnitId!: string | null;
  @Column() createdByUserId!: string;
  @Column() amountCents!: number;
  @Column({ default: '' }) description!: string;
  @Column({ default: 'pending' }) status!: 'pending' | 'approved' | 'rejected';
}
