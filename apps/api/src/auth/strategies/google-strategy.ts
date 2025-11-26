import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import googleAuthConfig from '../config/google-auth.config';
import { type ConfigType } from '@nestjs/config';
import { AuthService } from '../auth.service';
// const s = new Strategy({
// clientID,
// clientSecret,
// callbackURL,
// scope
// to get the auto complete
// })

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    @Inject(googleAuthConfig.KEY)
    private readonly configuration: ConfigType<typeof googleAuthConfig>,
    private readonly authService: AuthService,
  ) {
    super({
      clientID: configuration.clientID as string,
      clientSecret: configuration.clientSecret as string,
      callbackURL: configuration.callbackURL as string,
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,// dont use them
    refreshToken: string, // dont use them
    profile: any,
    done: VerifyCallback,
  ) {
    const user = await this.authService.validateGoogleUser({
      email: profile.emails[0].value,
      name: profile.displayName,
      password: '',
    });

    done(null, user); // req.user
  }
}
