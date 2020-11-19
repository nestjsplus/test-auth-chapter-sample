// src/users/users.service.ts
import { Injectable } from '@nestjs/common';
import { Pet, User } from './user.entity';

@Injectable()
export class UsersService {
  private readonly users: User[];

  constructor() {
    this.users = [
      new User('john', 'changeme', new Pet('alfred', 1)),
      new User('chris', 'secret', new Pet('gopher', 2)),
      new User('maria', 'guess', new Pet('jenny', 1)),
    ];
  }

  async findOne(username: string): Promise<User> {
    return this.users.find((user: User) => user.username === username);
  }
}
