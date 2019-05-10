import { PassportSerializer } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
@Injectable()
export class SessionSerializer extends PassportSerializer {
  serializeUser(user: any, done: Function): any {
    done(null, user);
  }
  deserializeUser(payload: any, done: Function): any {
    done(null, payload);
  }
}
