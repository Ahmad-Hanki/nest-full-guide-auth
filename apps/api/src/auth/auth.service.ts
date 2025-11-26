import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { hash, verify } from 'argon2';
import { AuthJwtPayload } from './types/auth-jwt.payload';
import { JwtService } from '@nestjs/jwt';
import refreshJwtConfig from './config/refresh-jwt.config';
import { type ConfigType } from '@nestjs/config';
@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    @Inject(refreshJwtConfig.KEY)
    private readonly refreshJwtOptions: ConfigType<typeof refreshJwtConfig>,
  ) {}
  async registerUser(body: CreateUserDto) {
    const user = await this.userService.findByEmail(body.email);
    if (user) {
      throw new ConflictException('User already exists');
    }
    const data = await this.userService.create(body);
    await this.login(data.id, data.name);
  }

  async validateLocalUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isSamePassword = await verify(user.password, password);
    if (!isSamePassword) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const { password: _, ...result } = user;
    return { id: result.id, name: result.name, role: result.role };
  }

  async login(userId: number, name?: string) {
    const { accessToken, refreshToken } = await this.generateTokens(userId);

    const hashedRefreshToken = await hash(refreshToken);
    await this.userService.updateHashedRefreshToken(userId, hashedRefreshToken);
    return {
      id: userId,
      name,
      accessToken,
      refreshToken,
    };
  }

  async generateTokens(userId: number) {
    const payload: AuthJwtPayload = { sub: userId }; // the payload we would like to include in the token

    const [accessToken, refreshToken] = await Promise.all([
      // first one to create access token
      this.jwtService.signAsync(payload),
      // second one to create refresh token
      this.jwtService.signAsync(payload, this.refreshJwtOptions),
    ]);

    return { accessToken, refreshToken };
  }

  async validateJwtUser(userId: number) {
    const user = await this.userService.findOne(+userId);
    if (!user) {
      throw new UnauthorizedException('Invalid token user');
    }
    const currentUser = { id: user.id, role: user.role };
    return currentUser;
  }

  async validateRefreshToken(userId: number, refreshToken: string) {
    const user = await this.userService.findOne(+userId);
    if (!user) {
      throw new UnauthorizedException('Invalid token user');
    }
    const refreshTokenMatched = await verify(
      user.hashedRefreshToken || '',
      refreshToken,
    );

    if (!refreshTokenMatched) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const currentUser = { id: user.id };
    return currentUser;
  }

  async refreshTokens(userId: number, name: string) {
    const { accessToken, refreshToken } = await this.generateTokens(userId);

    const hashedRefreshToken = await hash(refreshToken);
    await this.userService.updateHashedRefreshToken(userId, hashedRefreshToken); // invalidate old one
    return {
      id: userId,
      name,
      accessToken,
      refreshToken,
    };
  }

  async validateGoogleUser(googleUser: CreateUserDto) {
    const user = await this.userService.findByEmail(googleUser.email);

    if (user) {
      return user;
    }
    return await this.userService.create(googleUser);
  }

  logout(id: number) {
    return this.userService.updateHashedRefreshToken(id, null);
  }
}
