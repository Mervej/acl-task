import { Module } from '@nestjs/common';
import { ProfilesModule } from './profiles.module';

@Module({ imports: [ProfilesModule] })
export class AppModule {}
