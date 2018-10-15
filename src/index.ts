import * as express from 'express';
import * as bodyParser from 'body-parser';
import { ErrorCode, LogicError } from './services/errors.service';
import { logger } from './services/logger.service';
import { ErrorRequestHandler } from 'express';
import { router } from './rest-routes';
import { MessageHub } from './ws/message-hub.class';
import { emitters, subscribers } from './ws/event-handlers';

const app = express();

app.use(bodyParser.json());
app.use('/', router);
app.use(((err, req, res, next) => {
  if (err instanceof LogicError) {
    res.status(400).json(err);
  } else {
    logger.error(err);
    res.status(500).json(new LogicError(ErrorCode.SERVER));
  }
}) as ErrorRequestHandler);

const httpServer = app.listen(80);
const wsServer = new MessageHub(httpServer, subscribers, emitters, '/chat');

logger.log('started listening');
