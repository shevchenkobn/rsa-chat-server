"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const ws = require("websocket");
const errors_service_1 = require("../services/errors.service");
const auth_service_1 = require("../services/auth.service");
const url_1 = require("url");
const logger_service_1 = require("../services/logger.service");
class MessageHub {
    constructor(httpServer, subscribeEvents, emitEvents, chatPath = '/') {
        if (subscribeEvents.size === 0 || emitEvents.size === 0) {
            throw new Error('No events to manipulate found');
        }
        for (const event of MessageHub.serviceEmitEvents) {
            if (!emitEvents.has(event)) {
                throw new Error(`No "${event}" event emitter found`);
            }
        }
        this.httpServer = httpServer;
        this.subscribeEvents = subscribeEvents;
        this.emitEvents = emitEvents;
        this.chatPath = chatPath;
        this.server = new ws.server({
            httpServer,
        });
        const clients = [];
        this.clients = clients;
        this.server.on('request', (request) => {
            const url = request.httpRequest.url;
            if (!url || url_1.parse(url).pathname !== chatPath) {
                request.reject(404);
                return;
            }
            let user;
            try {
                user = auth_service_1.getUserFromHTTPRequest(request.httpRequest);
            }
            catch (err) {
                request.reject(401, JSON.stringify(new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_NO)));
                return;
            }
            if (this.clients.some(client => client.user.name === user.name)) {
                request.reject(400, JSON.stringify(new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_DUPLICATE_NAME)));
                return;
            }
            // FIXME: maybe other protocol scpecifying is needed
            const connection = request.accept(null, request.origin);
            const client = new MessageHub.Client(connection, user);
            this.emitEvents.get('client-created')(client, this);
            this.broadcast('user-joined', [], client);
            logger_service_1.logger.log(`Client ${client.user.name} connected`);
            clients.push(client);
            connection.on('error', (err) => {
                try {
                    this.emitEvents.get('error')(client, this, err);
                }
                catch (err) {
                    logger_service_1.logger.info('Error notification doesn\'t work');
                }
                logger_service_1.logger.error(`Connection ${client.user.name} is about to close due to ${err}`);
            });
            connection.on('message', (data) => {
                logger_service_1.logger.log(`Message from ${client.user.name}`);
                try {
                    const message = JSON.parse(data.utf8Data);
                    if (!message || typeof message.event !== 'string') {
                        throw new TypeError('Bad message');
                    }
                    logger_service_1.logger.log(`Event ${message.event}`);
                    const handler = subscribeEvents.get(message.event);
                    handler(client, this, message.data);
                }
                catch (err) {
                    this.emitEvents.get('error')(client, this, err);
                    logger_service_1.logger.error(`Error for ${client.user.name}:\nERROR: ${err}`);
                }
            });
            connection.on('close', (reason, desc) => {
                clients.splice(clients.indexOf(client), 1);
                this.broadcast('user-left', [], client);
                this.emitEvents.get('client-disposed')(client, this);
                logger_service_1.logger.log(`Disonnected ${client.user.name} because of ${reason} (${desc})`);
            });
        });
    }
    broadcast(event, excludeClients = [], ...args) {
        const emit = this.emitEvents.get(event);
        if (!emit) {
            throw new Error(`Bad emit event: ${event}`);
        }
        const clientsToBroadcast = this.clients.filter(client => !excludeClients.indexOf(client));
        for (const client of clientsToBroadcast) {
            emit(client, this, ...args);
        }
    }
}
MessageHub.serviceEmitEvents = [
    'error',
    'client-created',
    'user-joined',
    'user-left',
    'client-disposed',
];
exports.MessageHub = MessageHub;
(function (MessageHub) {
    class Client {
        constructor(connection, user) {
            this.connection = connection;
            this.user = user;
        }
        emit(event, payload) {
            this.connection.sendUTF(JSON.stringify({
                event,
                data: payload,
            }));
        }
    }
    MessageHub.Client = Client;
})(MessageHub = exports.MessageHub || (exports.MessageHub = {}));
//# sourceMappingURL=message-hub.class.js.map