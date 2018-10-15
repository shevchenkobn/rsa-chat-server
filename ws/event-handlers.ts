import { EventHandler, MessageHub } from './message-hub.class';
import {
  decrypt,
  encrypt,
  scheduleExpiration,
  setExpirationCallback,
} from '../src/services/key-manager.service';
import { ErrorCode, LogicError } from '../src/services/errors.service';
import { logger } from '../src/services/logger.service';

export const subscribers = new Map<string, EventHandler>([
  ['message-sent', (client, hub, encryptedMsg: string) => {
    const msg = decrypt(client.user.decryptKey, Buffer.from(encryptedMsg));
    hub.broadcast('message-received', [], msg);
  }],
]);

export const emitters = new Map<string, EventHandler>([
  ['message-received', (client, hub, msg: string) => {
    client.emit('message-received', {
      data: encrypt(client.user.encryptKey, msg),
    });
  }],

  ['client-created', (client, hub) => {
    scheduleExpiration(client.user.name, () => {
      client.emit('key-outdated', {});
    });
  }],

  ['user-joined', (currClient, hub, newClient: MessageHub.Client) => {
    currClient.emit('user-joined', {
      username: newClient.user.name,
    });
  }],

  ['user-left', (currClient, hub, newClient: MessageHub.Client) => {
    currClient.emit('user-left', {
      username: newClient.user.name,
    });
  }],

  ['client-disposed', (client, hub) => {
    setExpirationCallback(client.user.name, undefined);
  }],

  ['error', (currClient, hub, err: Error) => {
    currClient.emit('error', err instanceof LogicError ? err : new LogicError(ErrorCode.SERVER));
    logger.error(err);
  }],
]);
