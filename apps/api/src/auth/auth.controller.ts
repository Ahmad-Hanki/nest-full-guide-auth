import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { LocalAuthGuard } from './guards/local-auth/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth/jwt-auth.guard';
import { RefreshJwtAuthGuard } from './guards/refresh-jwt-auth/refresh-jwt-auth.guard';
import { GoogleAuthGuard } from './guards/google-auth/google-auth.guard';

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

  @UseGuards(GoogleAuthGuard)
  @Get('google')
  async googleLogin(@Request() req) {
    // initiates the Google OAuth2 login flow
    // this will call google/callback
  }

  @Get('google/callback') // same cllback in env
  @UseGuards(GoogleAuthGuard)
  async googleLoginCallback(@Request() req, @Res() res) {
    // handles the Google OAuth2 callback
    // WE SHOULD CREATE OUR OWN JWT TOKENS HERE
    const userData = await this.authService.login(req.user.id, req.user.name);
    res.redirect(
      `http://localhost:3000/api/auth/google/success?accessToken=${userData.accessToken}&refreshToken=${userData.refreshToken}`, // &role=${userData.role}
    );
  }

  @UseGuards(JwtAuthGuard)
  @Post('signout')
  async logout(@Request() req) {
    return await this.authService.logout(req.user.id);
  }
}
