// src/app.controller.ts
import {
  Controller,
  Get,
  Post,
  Request,
  Res,
  UseGuards,
  UseFilters,
} from '@nestjs/common';
import { Response } from 'express';
import { LoginGuard } from './common/guards/login.guard';
import { AuthenticatedGuard } from './common/guards/authenticated.guard';
import { AuthExceptionFilter } from './common/filters/auth-exceptions.filter';

@Controller()
@UseFilters(AuthExceptionFilter)
export class AppController {
  @Get('/')
  index(@Request() req, @Res() res: Response) {
    res.render('login', { message: req.flash('loginError') });
  }

  @UseGuards(LoginGuard)
  @Post('/login')
  login(@Request() req, @Res() res: Response) {
    res.redirect('/home');
  }

  @UseGuards(AuthenticatedGuard)
  @Get('/home')
  getHome(@Request() req, @Res() res: Response) {
    res.render('home', { user: req.user });
  }

  @UseGuards(AuthenticatedGuard)
  @Get('/profile')
  getProfile(@Request() req, @Res() res: Response) {
    res.render('profile', { user: req.user });
  }

  @Get('/logout')
  logout(@Request() req, @Res() res: Response) {
    req.logout();
    res.redirect('/');
  }
}
