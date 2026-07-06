import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { createTenantDataSourceResolver } from '../tenant/tenant-datasource';

@Module({
  controllers: [AuthController],
  providers: [
    {
      provide: AuthService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        return new AuthService(
          createTenantDataSourceResolver(redis),
          process.env.JWT_SECRET ?? 'dev-secret-change-me',
          Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 900),
        );
      },
    },
  ],
  exports: [AuthService],
})
export class AuthModule {}
