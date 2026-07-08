import 'reflect-metadata';
import Redis from 'ioredis';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { createTenantDataSourceResolver } from './tenant-datasource';
import { consumeAllTenants } from './discovery';

const CONSUMER_GROUP = 'audit-service';
const CONSUMER_NAME = `audit-instance-${process.pid}`;

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3009);

  const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379');
  const resolver = createTenantDataSourceResolver(redis);

  // consumeTenantStream blocks up to 5s per tenant, so a full pass can
  // exceed a fixed tick interval — loop sequentially instead so the next
  // pass never starts before the previous one finishes.
  void (async function pollLoop() {
    for (;;) {
      await consumeAllTenants(redis, resolver, CONSUMER_GROUP, CONSUMER_NAME).catch((err) => {
        console.error('Audit poll pass failed:', err);
      });
    }
  })();
}
bootstrap();
