import { ErrorCode, LogicError } from './errors.service';
import { User } from './user.class';
import { EventEmitter } from 'events';

const map = new Map<string, User>();

export const storage = new class extends EventEmitter {
  has(name: string) {
    return map.has(name);
  }

  get(name: string): User {
    const user = map.get(name);
    if (!user) {
      throw new LogicError(ErrorCode.AUTH_NO, `Invalid name ${name}`);
    }
    return user;
  }

  add(name: string): User {
    if (map.has(name)) {
      throw new LogicError(ErrorCode.AUTH_DUPLICATE_NAME);
    }

    const user = new User(name);
    map.set(name, user);
    return user;
  }

  delete(nameOrUser: string | User): User {
    const user = typeof nameOrUser === 'string'
      ? map.get(nameOrUser)
      : nameOrUser;
    if (!user) {
      throw new LogicError(ErrorCode.AUTH_NO);
    }
    map.delete(user.name);
    this.emit('deleted', user);
    return user;
  }
};
