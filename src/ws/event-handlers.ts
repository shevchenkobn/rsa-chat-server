import { EventHandler, MessageHub } from './message-hub.class';
import { decrypt, encrypt, keyExpiration, } from '../services/key-manager.service';
import { ErrorCode, LogicError } from '../services/errors.service';
import { logger } from '../services/logger.service';

export const subscribers = new Map<string, EventHandler>([
  ['message-sent', (client, hub, payload?: any | null) => {
    if (!(payload instanceof Object && 'message' in payload)) {
      logger.error('Ill-formed message');
      client.emit('error', new LogicError(ErrorCode.MSG_BAD));
      return;
    }
    const msg = decrypt(client.user.decryptKey, Buffer.from(payload.message));
    hub.broadcast('message-received', [], msg, client.user.name);
  }],
]);

export const emitters = new Map<string, EventHandler>([
  ['message-received', (client, hub, msg: string, username: string) => {
    client.emit('message-received', {
      username,
      message: encrypt(client.user.encryptKey, msg),
    });
  }],

  ['client-created', (client, hub) => {
    if (!keyExpiration.has(client.user.name)) {
      keyExpiration.schedule(client.user.name, () => {
        client.emit('key-outdated', {});
      });
    } else {
      keyExpiration.setCallback(client.user.name, () => {
        client.emit('key-outdated', {});
      });
    }
  }],

  ['user-joined', (currClient, hub, newClient: MessageHub.Client) => {
    currClient.emit('user-joined', {
      username: newClient.user.name,
    });
  }],

  ['user-left', (currClient, hub, oldClient: MessageHub.Client) => {
    currClient.emit('user-left', {
      username: oldClient.user.name,
    });
  }],

  ['client-disposed', (client, hub) => {
    keyExpiration.deleteCallback(client.user.name);
  }],

  ['error', (currClient, hub, err: Error) => {
    currClient.emit('error', err instanceof LogicError ? err : new LogicError(ErrorCode.SERVER));
    logger.error(err);
  }],
]);
