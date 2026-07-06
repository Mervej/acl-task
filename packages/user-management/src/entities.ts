import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('user_profiles')
export class UserProfile {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column() userId!: string;
  @Column() fullName!: string;
  @Column({ default: '' }) jobTitle!: string;
  @Column({ type: 'uuid', nullable: true }) managerId!: string | null;
  @Column({ type: 'uuid', nullable: true }) orgUnitId!: string | null;
  @Column({ type: 'date' }) hireDate!: string;
}
