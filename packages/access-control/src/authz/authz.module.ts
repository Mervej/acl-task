import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { AuthzController } from './authz.controller';
import { AuthzService } from './authz.service';
import { AuthService } from '../auth/auth.service';
import { UsersService } from '../users/users.service';
import { createTenantDataSourceResolver } from '../tenant/tenant-datasource';

@Module({
  controllers: [AuthzController],
  providers: [
    {
      provide: AuthzService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        const resolver = createTenantDataSourceResolver(redis);
        const authService = new AuthService(
          resolver,
          process.env.JWT_SECRET ?? 'dev-secret-change-me',
          Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 900),
        );
        const usersService = new UsersService(resolver);
        return new AuthzService(resolver, authService, usersService);
      },
    },
  ],
})
export class AuthzModule {}
