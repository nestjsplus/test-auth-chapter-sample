// src/api/api.controller.ts
import { Controller, Get, Request, Res, Post, UseGuards } from '@nestjs/common';
import { LoginGuard } from '../common/guards/login.guard';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth/auth.service';

@Controller('api')
export class ApiController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LoginGuard)
  @Post('/login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('/me')
  getProfile(@Request() req) {
    return req.user;
  }
}
