import * as jwt from 'jsonwebtoken';
import { verify } from 'jsonwebtoken';
import { User } from './user.class';
import { jwtConfig } from '../config/config';
import { storage } from './user-storage.service';
import { ErrorRequestHandler, Handler } from 'express';
import * as expressJwt from 'express-jwt';
import { ErrorCode, LogicError } from './errors.service';
import { logger } from './logger.service';
import { IncomingMessage } from 'http';

export function createToken(user: User) {
  return jwt.sign({ id: user.name }, jwtConfig.secret);
}

export function getUserFromPayload(obj: any) {
  if (!(obj instanceof Object) || !('id' in obj)) {
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
    logger.log(`User: ${req.user.name}`);
    next();
  }) as Handler,
];

const tokenSchemeRegex = /^Bearer$/;
const spaces = /\s+/;

function getJWTPayload(httpReq: IncomingMessage) {
  const authParts = (httpReq.headers.authorization as string)
    .split(spaces);
  if (authParts.length !== 2 || !tokenSchemeRegex.test(authParts[0])) {
    return null;
  }

  let payload;
  try {
    payload = verify(authParts[1], jwtConfig.secret);
  } catch (err) {
    logger.error(err);
    return null;
  }
  return payload;
}

export function getUserFromHTTPRequest(request: IncomingMessage) {
  const payload = getJWTPayload(request);

  if (payload instanceof Object && typeof (payload as any).id === 'string') {
    return storage.get((payload as any).id);
  }
  throw new LogicError(ErrorCode.AUTH_NO);
}
