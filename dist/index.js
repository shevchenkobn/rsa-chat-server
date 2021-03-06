"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express = require("express");
const bodyParser = require("body-parser");
const errors_service_1 = require("./services/errors.service");
const logger_service_1 = require("./services/logger.service");
const message_hub_class_1 = require("./ws/message-hub.class");
const event_handlers_1 = require("./ws/event-handlers");
const rest_routes_1 = require("./rest-routes");
const app = express();
app.use(bodyParser.json());
// app.use((req, res, next) => {
//   logger.log(req);
//   next();
// });
app.use('/', rest_routes_1.router);
app.use((req, res, next) => {
    res.status(404).json({});
});
app.use(((err, req, res, next) => {
    if (err instanceof errors_service_1.LogicError) {
        switch (err.code) {
            case errors_service_1.ErrorCode.AUTH_NO:
                res.status(401);
                break;
            case errors_service_1.ErrorCode.SERVER:
                res.status(500);
                break;
            default:
                res.status(400);
        }
        res.json(err);
    }
    else {
        logger_service_1.logger.error(err);
        res.status(500).json(new errors_service_1.LogicError(errors_service_1.ErrorCode.SERVER));
    }
}));
const port = process.env.PORT || 5000;
const httpServer = app.listen(port);
const wsServer = new message_hub_class_1.MessageHub(httpServer, event_handlers_1.subscribers, event_handlers_1.emitters, '/chat');
logger_service_1.logger.log(`started listening at ${port}`);
//# sourceMappingURL=index.js.map