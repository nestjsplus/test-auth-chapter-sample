// src/api/api.controller.ts
import { Controller, Get, Request, Res, Post, UseGuards } from '@nestjs/common';
import { Response } from 'express';
import { LoginGuard } from '../common/guards/login.guard';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth/auth.service';

@Controller('api')
export class ApiController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LoginGuard)
  @Post('/login')
  async login(@Request() req, @Res() res: Response) {
    const token = await this.authService.login(req.user);
    res.json(token);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('/me')
  getProfile(@Request() req, @Res() res: Response) {
    res.json(req.user);
  }
}
