import { Entity, PrimaryGeneratedColumn, Column, Unique } from 'typeorm';

@Entity('tenants')
export class Tenant {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() name!: string;
  @Column({ unique: true }) slug!: string;
  @Column({ default: 'active' }) status!: 'active' | 'suspended';
}

@Entity('tenant_db_registry')
@Unique(['tenantId', 'serviceName'])
export class TenantDbRegistry {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column() serviceName!: string;
  @Column() host!: string;
  @Column() port!: number;
  @Column() database!: string;
  @Column() username!: string;
  @Column() password!: string;
}

@Entity('permissions')
export class Permission {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column({ unique: true }) key!: string;
  @Column() description!: string;
}
