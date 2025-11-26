import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class RefreshJwtAuthGuard extends AuthGuard('refresh-jwt') {} // this is the key, it should match the strategy name
