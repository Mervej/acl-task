import { Body, Controller, ForbiddenException, Get, Headers, NotFoundException, Param, Post, Query, UnauthorizedException } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto';

@Controller('internal/users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async create(@Body() dto: CreateUserDto, @Headers('x-service-api-key') serviceApiKey?: string) {
    if (!serviceApiKey) throw new UnauthorizedException('Missing x-service-api-key header');
    const validKey = await this.usersService.verifyServiceApiKey(dto.tenantId, 'internal', serviceApiKey);
    if (!validKey) throw new UnauthorizedException('Invalid service API key');
    return this.usersService.createUser(dto.tenantId, dto.email, dto.password);
  }

  @Get(':userId')
  async get(
    @Param('userId') userId: string,
    @Query('tenantId') tenantId: string,
    @Headers('x-service-api-key') serviceApiKey?: string,
  ) {
    if (!serviceApiKey) throw new UnauthorizedException('Missing x-service-api-key header');
    const validKey = await this.usersService.verifyServiceApiKey(tenantId, 'internal', serviceApiKey);
    if (!validKey) throw new UnauthorizedException('Invalid service API key');
    const user = await this.usersService.getUser(tenantId, userId);
    if (!user) throw new NotFoundException('User not found');
    return user;
  }
}
