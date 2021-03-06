"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const key_manager_service_1 = require("../services/key-manager.service");
const errors_service_1 = require("../services/errors.service");
const logger_service_1 = require("../services/logger.service");
exports.subscribers = new Map([
    ['message-sent', (client, hub, payload) => {
            if (!(payload instanceof Object
                && (typeof payload.message === 'string'
                    || Array.isArray(payload.message)))) {
                logger_service_1.logger.error('Ill-formed message');
                client.emit('error', new errors_service_1.LogicError(errors_service_1.ErrorCode.MSG_BAD));
                return;
            }
            // const sampleMsg = Buffer.from('Hello, fuckers))))').toString('base64');
            // const encrypted = encrypt(client.user.encryptKey, Buffer.from(sampleMsg, 'base64'));
            // logger.debug(encrypted.toString('base64'));
            // logger.debug(
            //   decrypt(
            //     client.user.remotePrivateKey,
            //     encrypted,
            //   ).toString('utf8'),
            // );
            let srcBuffer = Buffer.from(payload.message, 'base64');
            // srcBuffer = srcBuffer.slice(
            //   0,
            //   srcBuffer.length - srcBuffer.length % 512,
            // );
            const msgBuffer = key_manager_service_1.decrypt(client.user.decryptKey, srcBuffer);
            logger_service_1.logger.debug(JSON.stringify(msgBuffer.toString('utf8')));
            hub.broadcast('message-received', [], msgBuffer, client.user.name);
        }],
]);
exports.emitters = new Map([
    ['message-received', (client, hub, msg, username) => {
            client.emit('message-received', {
                username,
                // message: encrypt(client.user.encryptKey, msg).toString('base64'),
                message: [...key_manager_service_1.encrypt(client.user.encryptKey, msg).values()],
            });
        }],
    ['client-created', (client, hub) => {
            const callback = (err) => {
                if (err) {
                    hub.emitEvents.get('error')(client, hub, err);
                }
                else {
                    client.emit('key-outdated', {});
                }
            };
            if (!key_manager_service_1.keyExpiration.has(client.user.name)) {
                key_manager_service_1.keyExpiration.schedule(client.user.name, callback);
            }
            else {
                key_manager_service_1.keyExpiration.setCallback(client.user.name, callback);
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
            currClient.emit('error', err instanceof errors_service_1.LogicError ? err : new errors_service_1.LogicError(errors_service_1.ErrorCode.MSG_BAD));
            logger_service_1.logger.error(err);
        }],
]);
//# sourceMappingURL=event-handlers.js.map