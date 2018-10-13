import { IncomingMessage, Server as HttpServer } from 'http';
import { server as WSServer } from 'websocket';
import { ErrorCode, LogicError } from '../src/services/errors.service';
import { verify } from 'jsonwebtoken';
import { logger } from '../src/services/logger.service';
import { jwtConfig, keyConfig } from '../src/config/config';

const tokenSchemeRegex = /^Bearer$/;
const spaces = /^\s+/;

function getJWTPayload(httpReq: IncomingMessage) {
  const authParts = (httpReq.headers.authorization as string)
    .split(spaces);
  if (authParts.length !== 2 || tokenSchemeRegex.test(authParts[0])) {
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

export function createServer(httpServer: HttpServer) {
  const server = new WSServer({
    httpServer,
  });

  server.on('request', (request) => {
    // const httpReq = request.httpRequest;


  });

  return server;
}
