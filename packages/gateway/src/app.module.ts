import { Module } from '@nestjs/common';
import { ProxyModule } from './proxy.module';

@Module({ imports: [ProxyModule] })
export class AppModule {}
