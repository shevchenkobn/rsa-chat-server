import * as jwt from 'jsonwebtoken';
import { User } from './user.class';
import { jwtConfig } from '../config/config';
import { storage } from './user-storage.service';
import { ErrorRequestHandler, Handler, Request } from 'express';
import * as expressJwt from 'express-jwt';
import { ErrorCode, LogicError } from './errors.service';
import { logger } from './logger.service';
import { ErrorHandleFunction } from 'connect';

export function createToken(user: User) {
  return jwt.sign({ id: user.name}, jwtConfig.secret);
}

export function getUserFromPayload(obj: any) {
  if (typeof obj !== 'object' || !('id' in obj)) {
    throw new LogicError(ErrorCode.AUTH_NO);
  }
  const name: string = obj.id;
  return storage.get(name);
}

export const authMiddlewares: ReadonlyArray<Handler | ErrorRequestHandler> = [
  expressJwt({ secret: jwtConfig.secret }),
  (err, req, res, next) => {
    logger.error(err);
    res.status(401).json(new LogicError(ErrorCode.AUTH_NO));
  },
  ((req, res, next) => {
    req.user = getUserFromPayload(req.user);
    next();
  }) as Handler,
];
