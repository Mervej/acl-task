import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { createTenantDataSourceResolver } from '../tenant/tenant-datasource';

@Module({
  controllers: [UsersController],
  providers: [
    {
      provide: UsersService,
      useFactory: () => {
        const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
        return new UsersService(createTenantDataSourceResolver(redis));
      },
    },
  ],
  exports: [UsersService],
})
export class UsersModule {}
