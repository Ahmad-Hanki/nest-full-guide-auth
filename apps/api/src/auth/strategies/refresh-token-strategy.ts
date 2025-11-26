import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { ConfigType } from '@nestjs/config'; // 👈 type-only import
import jwtConfig from '../config/jwt.config';
import { AuthService } from '../auth.service';
import { type AuthJwtPayload } from '../types/auth-jwt.payload';
import refreshJwtConfig from '../config/refresh-jwt.config';
import { Request } from 'express';

@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(
  Strategy,
  'refresh-jwt',
) {
  constructor(
    @Inject(refreshJwtConfig.KEY)
    private readonly refreshJwtConfiguration: ConfigType<
      typeof refreshJwtConfig
    >,
    private readonly authService: AuthService,
  ) {
    if (!refreshJwtConfiguration.secret) {
      // runtime safety + lets TS know secret is string after this
      throw new Error('JWT secret is not defined in configuration');
    }

    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refreshToken'), // i take it from body
      secretOrKey: refreshJwtConfiguration.secret as string,
      ignoreExpiration: false,
      passReqToCallback: true, // to get req in validate
    });
  }

  // when a request comes in with a JWT token, it will call this validate method and send pass the payload
  async validate(req: Request, payload: AuthJwtPayload) {
    const refreshToken = req.body.refreshToken; // for the invalidate

    const userId = payload.sub;
    return await this.authService.validateRefreshToken(+userId, refreshToken); // req.user
  }
}
