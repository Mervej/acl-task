import { Injectable, UnauthorizedException } from '@nestjs/common';
import { In } from 'typeorm';
import bcrypt from 'bcrypt';
import type { TenantConnectionResolver } from '@platform/auth-kit';
import { signAccessToken } from '@platform/auth-kit';
import { controlPlaneDataSource } from '../control-plane/data-source';
import { Tenant } from '../control-plane/entities';
import { User, Role, RolePermission, RoleAssignment, RefreshToken } from '../tenant/entities';
import { verifyPassword, hashSecret } from '../password';
import { randomBytes } from 'crypto';

// Precomputed once at module load so that login() always pays the cost of a
// bcrypt comparison, even when the user (and therefore a real password hash)
// doesn't exist. Without this, "unknown email" would return faster than
// "known email, wrong password", letting an attacker enumerate valid emails
// within a tenant via response timing.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('dummy-password-for-timing-safety', 10);

@Injectable()
export class AuthService {
  constructor(
    private readonly resolver: TenantConnectionResolver,
    private readonly jwtSecret: string,
    private readonly accessTokenTtlSeconds: number,
  ) {}

  async resolveEffectivePermissions(
    tenantId: string,
    userId: string,
  ): Promise<{ roles: string[]; permissions: string[]; orgUnitId: string | null }> {
    const dataSource = await this.resolver.getConnection(tenantId);
    const assignments = await dataSource
      .getRepository(RoleAssignment)
      .find({ where: { tenantId, userId } });
    if (assignments.length === 0) return { roles: [], permissions: [], orgUnitId: null };

    const roleIds = assignments.map((a) => a.roleId);
    const roles = await dataSource.getRepository(Role).find({ where: { id: In(roleIds) } });
    const rolePermissions = await dataSource
      .getRepository(RolePermission)
      .find({ where: { roleId: In(roleIds) } });

    const permissions = [...new Set(rolePermissions.map((rp) => rp.permissionKey))];
    const orgUnitId = assignments.find((a) => a.orgUnitId !== null)?.orgUnitId ?? null;

    return { roles: roles.map((r) => r.name), permissions, orgUnitId };
  }

  async login(
    tenantSlug: string,
    email: string,
    password: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const tenant = await controlPlaneDataSource
      .getRepository(Tenant)
      .findOne({ where: { slug: tenantSlug, status: 'active' } });
    if (!tenant) throw new UnauthorizedException('Unknown tenant');

    const dataSource = await this.resolver.getConnection(tenant.id);
    const user = await dataSource
      .getRepository(User)
      .findOne({ where: { tenantId: tenant.id, email, status: 'active' } });
    const passwordValid = await verifyPassword(password, user ? user.passwordHash : DUMMY_PASSWORD_HASH);
    if (!user || !passwordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { roles, permissions, orgUnitId } = await this.resolveEffectivePermissions(
      tenant.id,
      user.id,
    );

    const accessToken = signAccessToken(
      { sub: user.id, tenantId: tenant.id, roles, permissions, orgUnitId },
      this.jwtSecret,
      this.accessTokenTtlSeconds,
    );

    const refreshTokenPlain = randomBytes(32).toString('hex');
    const refreshTokenRepo = dataSource.getRepository(RefreshToken);
    await refreshTokenRepo.save(
      refreshTokenRepo.create({
        tenantId: tenant.id,
        userId: user.id,
        tokenHash: hashSecret(refreshTokenPlain),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        revokedAt: null,
      }),
    );

    return { accessToken, refreshToken: refreshTokenPlain };
  }
}
