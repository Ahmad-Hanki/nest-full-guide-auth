import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { LocalAuthGuard } from './guards/local-auth/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth/jwt-auth.guard';
import { RefreshJwtAuthGuard } from './guards/refresh-jwt-auth/refresh-jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async registerUser(@Body() body: CreateUserDto) {
    return await this.authService.registerUser(body);
  }

  @UseGuards(LocalAuthGuard)
  @Post('signin')
  async login(@Request() req) {
    // req body
    return await this.authService.login(req.user.id, req.user.name);
  }

  @UseGuards(JwtAuthGuard)
  @Get('protected')
  getProtectedResource(@Request() req) {
    return {
      message: 'This is a protected resource',
      user: req.user,
    };
  }

  @UseGuards(RefreshJwtAuthGuard)
  @Post('refresh-token')
  async refreshToken(@Request() req) {
    return await this.authService.refreshTokens(req.user.id, req.user.name);
  }
}
