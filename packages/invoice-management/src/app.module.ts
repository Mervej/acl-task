import { Module } from '@nestjs/common';
import { InvoiceController } from './invoices.controller';

@Module({ controllers: [InvoiceController] })
export class AppModule {}
