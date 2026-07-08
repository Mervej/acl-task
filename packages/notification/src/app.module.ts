import { Module } from '@nestjs/common';
import { NotificationController } from './notifications.controller';

@Module({ controllers: [NotificationController] })
export class AppModule {}
