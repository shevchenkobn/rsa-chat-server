import * as express from 'express';
import { ErrorRequestHandler } from 'express';
import * as bodyParser from 'body-parser';
import { ErrorCode, LogicError } from './services/errors.service';
import { logger } from './services/logger.service';
import { MessageHub } from './ws/message-hub.class';
import { emitters, subscribers } from './ws/event-handlers';
import { router } from './rest-routes';

const app = express();

app.use(bodyParser.json());
// app.use((req, res, next) => {
//   logger.log(req);
//   next();
// });
app.use('/', router);
app.use((req, res, next) => {
  res.status(404).json({});
});
app.use(((err, req, res, next) => {
  if (err instanceof LogicError) {
    switch (err.code) {
      case ErrorCode.AUTH_NO:
        res.status(401);
        break;

      case ErrorCode.SERVER:
        res.status(500);
        break;

      default:
        res.status(400);
    }
    res.json(err);
  } else {
    logger.error(err);
    res.status(500).json(new LogicError(ErrorCode.SERVER));
  }
}) as ErrorRequestHandler);

const httpServer = app.listen(3000);
const wsServer = new MessageHub(httpServer, subscribers, emitters, '/chat');

logger.log('started listening');
