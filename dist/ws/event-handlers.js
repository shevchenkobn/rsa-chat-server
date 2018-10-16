"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const key_manager_service_1 = require("../services/key-manager.service");
const errors_service_1 = require("../services/errors.service");
const logger_service_1 = require("../services/logger.service");
exports.subscribers = new Map([
    ['message-sent', (client, hub, payload) => {
            if (!(payload instanceof Object && 'message' in payload)) {
                logger_service_1.logger.error('Ill-formed message');
                client.emit('error', new errors_service_1.LogicError(errors_service_1.ErrorCode.MSG_BAD));
                return;
            }
            const msg = key_manager_service_1.decrypt(client.user.decryptKey, Buffer.from(payload.message));
            hub.broadcast('message-received', [], msg, client.user.name);
        }],
]);
exports.emitters = new Map([
    ['message-received', (client, hub, msg, username) => {
            client.emit('message-received', {
                username,
                message: key_manager_service_1.encrypt(client.user.encryptKey, msg),
            });
        }],
    ['client-created', (client, hub) => {
            if (!key_manager_service_1.keyExpiration.has(client.user.name)) {
                key_manager_service_1.keyExpiration.schedule(client.user.name, () => {
                    client.emit('key-outdated', {});
                });
            }
            else {
                key_manager_service_1.keyExpiration.setCallback(client.user.name, () => {
                    client.emit('key-outdated', {});
                });
            }
        }],
    ['user-joined', (currClient, hub, newClient) => {
            currClient.emit('user-joined', {
                username: newClient.user.name,
            });
        }],
    ['user-left', (currClient, hub, oldClient) => {
            currClient.emit('user-left', {
                username: oldClient.user.name,
            });
        }],
    ['client-disposed', (client, hub) => {
            key_manager_service_1.keyExpiration.deleteCallback(client.user.name);
        }],
    ['error', (currClient, hub, err) => {
            currClient.emit('error', err instanceof errors_service_1.LogicError ? err : new errors_service_1.LogicError(errors_service_1.ErrorCode.SERVER));
            logger_service_1.logger.error(err);
        }],
]);
//# sourceMappingURL=event-handlers.js.map