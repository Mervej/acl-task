import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { controlPlaneDataSource } from './control-plane/data-source';

async function bootstrap() {
  await controlPlaneDataSource.initialize();
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3001);
}
bootstrap();
