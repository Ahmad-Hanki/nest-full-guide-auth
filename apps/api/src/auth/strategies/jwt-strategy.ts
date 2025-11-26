import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { ConfigType } from '@nestjs/config'; // 👈 type-only import
import jwtConfig from '../config/jwt.config';
import { AuthService } from '../auth.service';
import { type AuthJwtPayload } from '../types/auth-jwt.payload';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(jwtConfig.KEY)
    private readonly authService: AuthService,
  ) {
    const secret = jwtConfiguration.secret;

    if (!secret) {
      // runtime safety + lets TS know secret is string after this
      throw new Error('JWT secret is not defined in configuration');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: secret as string,
      ignoreExpiration: false,
    });
  }

  // when a request comes in with a JWT token, it will call this validate method and send pass the payload
  async validate(payload: AuthJwtPayload) {
    const userId = payload.sub;
    return this.authService.validateJwtUser(+userId);
  }
}
