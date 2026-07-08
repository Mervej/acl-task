import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity('audit_events')
export class AuditEventRecord {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column({ type: 'uuid', nullable: true }) actorUserId!: string | null;
  @Column() service!: string;
  @Column() action!: string;
  @Column() resourceType!: string;
  @Column({ type: 'varchar', nullable: true }) resourceId!: string | null;
  @Column() decision!: 'allow' | 'deny';
  @Column({ type: 'varchar', nullable: true }) viaService!: string | null;
  @Column({ type: 'text', nullable: true }) metadata!: string | null;
  @Column({ type: 'timestamptz' }) occurredAt!: Date;
}
