import { Entity, PrimaryGeneratedColumn, Column, Unique } from 'typeorm';

@Entity('users')
@Unique(['tenantId', 'email'])
export class User {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column() email!: string;
  @Column() passwordHash!: string;
  @Column({ default: 'active' }) status!: 'active' | 'disabled';
}

@Entity('org_units')
export class OrgUnit {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column() name!: string;
  @Column({ type: 'uuid', nullable: true }) parentId!: string | null;
}

@Entity('roles')
export class Role {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column() name!: string;
  @Column({ default: '' }) description!: string;
  @Column({ default: false }) isSystemRole!: boolean;
}

@Entity('role_permissions')
export class RolePermission {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() roleId!: string;
  @Column() permissionKey!: string;
}

@Entity('role_assignments')
export class RoleAssignment {
  @PrimaryGeneratedColumn('uuid') id!: string;
  @Column() tenantId!: string;
  @Column() userId!: string;
  @Column() roleId!: string;
  @Column({ type: 'uuid', nullable: true }) orgUnitId!: string | null;
}
