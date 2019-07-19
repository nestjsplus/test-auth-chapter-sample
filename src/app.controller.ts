// src/app.controller.ts
import {
  Controller,
  Get,
  Post,
  Request,
  Res,
  Render,
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
  @Render('login')
  index(@Request() req, @Res() res: Response): {message: string} {
    return { message: req.flash('loginError') };
  }

  @UseGuards(LoginGuard)
  @Post('/login')
  login(@Request() req, @Res() res: Response): void {
    res.redirect('/home');
  }

  @UseGuards(AuthenticatedGuard)
  @Get('/home')
  @Render('home')
  getHome(@Request() req, @Res() res: Response): {user: any } {
    return { user: req.user };
  }

  @UseGuards(AuthenticatedGuard)
  @Get('/profile')
  @Render('profile')
  getProfile(@Request() req: any, @Res() res: Response): {user: any} {
    return { user: req.user };
  }

  @Get('/logout')
  logout(@Request() req, @Res() res: Response): void {
    req.logout();
    res.redirect('/');
  }
}
