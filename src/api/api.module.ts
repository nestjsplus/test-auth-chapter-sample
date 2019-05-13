import { Module } from '@nestjs/common';
import { ApiController } from './api.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  controllers: [ApiController],
  imports: [AuthModule],
})
export class ApiModule {}
