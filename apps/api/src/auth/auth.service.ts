import { ConflictException, Injectable } from '@nestjs/common';
import { CreateUserDto } from '../user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';

@Injectable()
export class AuthService {
  constructor(private readonly userService: UserService) {}
  async registerUser(body: CreateUserDto) {
    const user = await this.userService.findByEmail(body.email);
    if (user) {
      throw new ConflictException('User already exists');
    }
    return this.userService.create(body);
  }
}
