import { Server as HttpServer } from 'http';
import * as ws from 'websocket';
import { ErrorCode, LogicError } from '../src/services/errors.service';
import { getUserFromHTTPRequest } from '../src/services/auth.service';
import { parse } from 'url';
import { User } from '../src/services/user.class';
import { logger } from '../src/services/logger.service';

export const CHAT_PATH = '/chat';

export type EventHandler = (
  (client: MessageHub.Client, messageHub: MessageHub, ...args: any[]) => void
);
export type MessageHandlers = ReadonlyMap<string, EventHandler>;

export class MessageHub {
  static readonly serviceEmitEvents: ReadonlyArray<string> = [
    'error',
    'client-created',
    'user-joined',
    'user-left',
    'client-disposed',
  ];

  readonly server: ws.server;
  readonly httpServer: HttpServer;
  readonly subscribeEvents: MessageHandlers;
  readonly emitEvents: MessageHandlers;
  readonly clients: ReadonlyArray<MessageHub.Client>;

  constructor(
    httpServer: HttpServer,
    subscribeEvents: MessageHandlers,
    emitEvents: MessageHandlers,
  ) {
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
    this.emitEvents = subscribeEvents;
    this.server = new ws.server({
      httpServer,
    });

    const clients: MessageHub.Client[] = [];
    this.clients = clients;

    this.server.on('request', (request) => {
      const url = request.httpRequest.url;
      if (!url || parse(url).pathname !== CHAT_PATH) {
        request.reject(404);
        return;
      }

      let user: User;
      try {
        user = getUserFromHTTPRequest(request.httpRequest);
      } catch (err) {
        request.reject(401, JSON.stringify(new LogicError(ErrorCode.AUTH_NO)));
        return;
      }

      // FIXME: maybe other protocol scpecifying is needed
      const connection = request.accept(null as any, request.origin);
      const client = new MessageHub.Client(connection, user);
      this.emitEvents.get('client-created')!(client, this);
      this.broadcast('user-joined', [], client);
      clients.push(client);

      connection.on('error', (err) => {
        try {
          this.emitEvents.get('error')!(client, this, err);
        } catch (err) {
          logger.info('Error notification doesn\'t work');
        }
        logger.error(`Connection ${connection} is about to close due to ${err}`);
      });

      connection.on('message', (data) => {
        try {
          const message = JSON.parse(data.utf8Data as string);
          if (!message || typeof message.event !== 'string') {
            throw new TypeError('Bad message');
          }

          const handler = subscribeEvents.get(message.event);

          handler!(client, this);
        } catch (err) {
          this.emitEvents.get('error')!(client, this, new LogicError(ErrorCode.MSG_BAD));
          console.error(err);
        }
      });

      connection.on('close', (reason, desc) => {
        clients.splice(clients.indexOf(client), 1);
        this.broadcast('user-left', [], client);
        this.emitEvents.get('client-disposed')!(client, this);
        logger.log(`Disonnected ${connection} because of ${reason} (${desc})`);
      });
    });
  }

  broadcast(event: string, excludeClients: ReadonlyArray<MessageHub.Client> = [], ...args: any[]) {
    const emit = this.emitEvents.get(event);
    if (!emit) {
      throw new Error(`Bad emit event: ${event}`);
    }
    const clientsToBroadcast = this.clients.filter(client => !excludeClients.indexOf(client));

    for (const client of clientsToBroadcast) {
      emit!(client, this, ...args);
    }
  }
}

export namespace MessageHub {
  export class Client {
    constructor(public readonly connection: ws.connection, public readonly user: User) {}

    emit(event: string, payload: object) {
      this.connection.sendUTF(JSON.stringify({
        event,
        data: payload,
      }));
    }
  }
}
