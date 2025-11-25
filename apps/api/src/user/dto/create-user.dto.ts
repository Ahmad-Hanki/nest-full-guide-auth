import { IsEmail, IsString, MinLength } from 'class-validator';

export class CreateUserDto {
  //npm i class-validator
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsString()
  @MinLength(5)
  password: string;
}
