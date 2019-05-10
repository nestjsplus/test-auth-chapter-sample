// auth.service.ts
import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(private readonly usersService: UsersService) { }

  async validateUser(username, password): Promise<any> {
    const user = await this.usersService.findOne(username);
    return user && user.password === password ? user : null;
  }
}