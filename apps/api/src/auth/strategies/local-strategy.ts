import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';
import { Injectable } from '@nestjs/common';

// const s = new Strategy({
// get teh auto complete
// });

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({
      usernameField: 'email',
      // passwordField: 'password',
    });
  }

  // when the local strategy is called, it will call this validate method
  async validate(email: string, password: string) {
    // validate them here
    return await this.authService.validateLocalUser(email, password);
    // the returned object will be attached to req.user
  }
}
