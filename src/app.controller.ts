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
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { LoginDTO } from './login.dto';

@Controller()
@UseFilters(AuthExceptionFilter)
export class AppController {

  @ApiOperation({ summary: 'Login Page' })
  @Get('/')
  @Render('login')
  index(@Request() req, @Res() res: Response): { message: string } {
    return { message: req.flash('loginError') };
  }

  @ApiOperation({ summary: 'Login on Local Strategy' })
  @ApiBody({ type: LoginDTO })
  @UseGuards(LoginGuard)
  @Post('/login')
  login(@Request() req, @Res() res: Response): void {
    res.redirect('/home');
  }

  @ApiOperation({ summary: 'Home Page' })
  @UseGuards(AuthenticatedGuard)
  @Get('/home')
  @Render('home')
  getHome(@Request() req, @Res() res: Response): { user: any } {
    return { user: req.user };
  }

  @ApiOperation({ summary: 'Profile Page' })
  @UseGuards(AuthenticatedGuard)
  @Get('/profile')
  @Render('profile')
  getProfile(@Request() req: any, @Res() res: Response): { user: any } {
    return { user: req.user };
  }

  @ApiOperation({ summary: 'Logout' })
  @Get('/logout')
  logout(@Request() req, @Res() res: Response): void {
    req.logout();
    res.redirect('/');
  }
}
