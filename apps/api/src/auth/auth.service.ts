import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { verify } from 'argon2';
import { AuthJwtPayload } from './types/auth-jwt.payload';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
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
    return result;
  }

  async login(userId: number, name?: string) {
    const { accessToken } = await this.generateJwtToken(userId);
    return {
      id: userId,
      name,
      accessToken,
    };
  }

  async generateJwtToken(userId: number) {
    const payload: AuthJwtPayload = { sub: userId }; // the payload we would like to include in the token

    const [accessToken] = await Promise.all([
      // first one to create access token
      this.jwtService.signAsync(payload),
    ]);

    return { accessToken };
  }

  async validateJwtUser(userId: number) {
    const user = await this.userService.findOne(+userId);
    if (!user) {
      throw new UnauthorizedException('Invalid token user');
    }
    const currentUser = { id: user.id };
    return currentUser;
  }
}
