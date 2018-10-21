import { EventHandler, MessageHub } from './message-hub.class';
import {
  decrypt,
  encrypt,
  keyExpiration,
  KeyExpiredCallback
} from '../services/key-manager.service';
import { ErrorCode, LogicError } from '../services/errors.service';
import { logger } from '../services/logger.service';

export const subscribers = new Map<string, EventHandler>([
  ['message-sent', (client, hub, payload?: any | null) => {
    if (!(
      payload instanceof Object
      && (
        typeof payload.message === 'string'
        || Array.isArray(payload.message)
      )
    )) {
      logger.error('Ill-formed message');
      client.emit('error', new LogicError(ErrorCode.MSG_BAD));
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

    const msgBuffer = decrypt(client.user.decryptKey, Buffer.from(payload.message, 'base64'));
    hub.broadcast('message-received', [], msgBuffer, client.user.name);
  }],
]);

export const emitters = new Map<string, EventHandler>([
  ['message-received', (client, hub, msg: Buffer, username: string) => {
    client.emit('message-received', {
      username,
      // message: encrypt(client.user.encryptKey, msg).toString('base64'),
      message: [...encrypt(client.user.encryptKey, msg).values()],
    });
  }],

  ['client-created', (client, hub) => {
    const callback: KeyExpiredCallback = (err) => {
      if (err) {
        hub.emitEvents.get('error')!(client, hub, err);
      } else {
        client.emit('key-outdated', {});
      }
    };
    if (!keyExpiration.has(client.user.name)) {
      keyExpiration.schedule(client.user.name, callback);
    } else {
      keyExpiration.setCallback(client.user.name, callback);
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
    currClient.emit('error', err instanceof LogicError ? err : new LogicError(ErrorCode.MSG_BAD));
    logger.error(err);
  }],
]);
