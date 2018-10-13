import * as express from 'express';
import * as bodyParser from 'body-parser';
import { ErrorCode, LogicError } from './services/errors.service';
import { logger } from './services/logger.service';
import { ErrorRequestHandler } from 'express';
import { router } from './rest-routes';

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
