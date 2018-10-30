import * as crypto from 'crypto';
import { privateDecrypt, publicEncrypt } from 'crypto';
import * as RsaKey from 'node-rsa';
import { keyConfig } from '../config/config';
import { storage } from './user-storage.service';
import { ErrorCode, LogicError } from './errors.service';
import { User } from './user.class';
import { logger } from './logger.service';
const CRYPTO_CONSTANTS: {[constant: string]: number} = (crypto as any).constants;

const generateKeyPair = (crypto as any).generateKeyPair;

const RSA_PADDING = new Map<number, number>([
  [CRYPTO_CONSTANTS.RSA_PKCS1_PADDING, 11],
  [CRYPTO_CONSTANTS.RSA_PKCS1_OAEP_PADDING, 41],
  [CRYPTO_CONSTANTS.RSA_NO_PADDING, 0],
]);

function getChunkSize(keyBits: number, type: number) {
  const size = (keyBits / 8) >>> 0;
  return size - RSA_PADDING.get(type)!;
}
const chunkSizes = [
  getChunkSize(keyConfig.size, CRYPTO_CONSTANTS.RSA_PKCS1_PADDING),
  getChunkSize(keyConfig.size, CRYPTO_CONSTANTS.RSA_NO_PADDING),
];
logger.debug(chunkSizes);

export interface RsaKeyPair {
  publicKey: string;
  privateKey: string;
}

export const generateKeyFormats = {
  publicKeyEncoding: {
    type: 'pkcs1',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs1',
    format: 'pem',
  },
};

export function generateKeys(): Promise<RsaKeyPair> {
  return new Promise((resolve, reject) => {
    generateKeyPair(keyConfig.type, {
      modulusLength: keyConfig.size,
      ...generateKeyFormats,
    }, (err: any | null | undefined, publicKey: string, privateKey: string) => {
      if (err) {
        reject(err);
        return;
      }
      resolve({ publicKey, privateKey });
    });
  });
}

export function encrypt(key: string, buffer: Buffer) {
  const buffers = [];
  const [chunkSize] = chunkSizes;
  logger.debug(buffer.length, chunkSize);
  for (let i = 0; i < buffer.length; i += chunkSize) {
    logger.debug(`${i} - ${i + chunkSize}`);
    buffers.push(
      publicEncrypt({
        key,
        padding: CRYPTO_CONSTANTS.RSA_PKCS1_PADDING,
      }, buffer.slice(i, i + chunkSize)),
    );
  }
  return Buffer.concat(buffers);
}

export function decrypt(key: string, buffer: Buffer) {
  const buffers = [];
  const [, chunkSize] = chunkSizes;
  for (let i = 0; i < buffer.length; i += chunkSize) {
    logger.debug(`${i} - ${i + chunkSize}`);
    buffers.push(
      privateDecrypt({
        key,
        padding: CRYPTO_CONSTANTS.RSA_PKCS1_PADDING,
      }, buffer.slice(i, i + chunkSize)),
    );
  }
  return Buffer.concat(buffers);
}

export type KeyExpiredCallback = (err: any | null, user: User | null) => void;
const scheduledExpirations = new Map<string, [NodeJS.Timeout, KeyExpiredCallback?]>();

export const keyExpiration = {
  has(userName: string) {
    return scheduledExpirations.has(userName);
  },

  schedule(userName: string, callback?: KeyExpiredCallback) {
    if (scheduledExpirations.has(userName)) {
      throw new LogicError(ErrorCode.SERVER);
    }
    const timeout = setTimeout(() => {
      let error = null;
      let user = null;
      let timeout;
      let callback;
      try {
        user = storage.get(userName);
        user.deleteKeys();

        [timeout, callback] = scheduledExpirations.get(userName)!;
        // FIXME: maybe not needed
        clearTimeout(timeout);
      } catch (err) {
        error = err;
      }
      if (callback) {
        callback(error, user);
      }
      scheduledExpirations.delete(userName);
    }, keyConfig.expireTime);
    scheduledExpirations.set(userName, [timeout, callback]);
  },

  delete(userName: string) {
    const scheduled = scheduledExpirations.get(userName);
    if (!scheduled) {
      logger.warn(`No scheduled key removal for ${userName}`);
      return;
    }

    clearTimeout(scheduled[0]);
    scheduledExpirations.delete(userName);
  },

  hasCallback(userName: string) {
    const scheduled = scheduledExpirations.get(userName);
    return !!(scheduled && scheduled[1]);
  },

  setCallback(userName: string, callback: KeyExpiredCallback) {
    const scheduled = scheduledExpirations.get(userName);
    if (!scheduled) {
      logger.warn(`No scheduled key removal for ${userName}`);
      return;
    }

    scheduled[1] = callback;
  },

  deleteCallback(userName: string) {
    const scheduled = scheduledExpirations.get(userName);
    if (!scheduled) {
      logger.warn(`No scheduled key removal for ${userName}`);
      return;
    }

    scheduled[1] = undefined;
  },
};

storage.on('deleted', (user: User) => {
  keyExpiration.delete(user.name);
  logger.log(`keyExpiration for ${user.name} is deleted`);
});

export class PublicKey {
  static allowedKeySources: ReadonlyArray<string> = [
    'string',
    'object',
  ];
  static allowedKeyFormats: ReadonlyArray<string> = [
    'pkcs1-public-der',
    'pkcs1-public-pem',
    'base64',
  ];

  readonly components: Readonly<{
    e: number;
    n: Buffer;
  }>;
  private _rsaKey: RsaKey;

  constructor(source: any, format?: string) {
    const sourceType = typeof source;
    this._rsaKey = new RsaKey();
    switch (sourceType) {
      case 'string':
        if (format === 'pkcs1-public-pem') {
          this._rsaKey.importKey(source, format);
        } else {
          throw new LogicError(ErrorCode.SERVER, `Only pkcs1-public-pem is allowed, not ${format}`);
        }
        break;

      case 'object':
        if (format === 'pkcs1-public-der' && source instanceof Buffer) {
          this._rsaKey.importKey(source, format);
          break;
        }
        if (
          typeof source.n === 'string'
          && format === 'base64'
        ) {
          source.n = Buffer.from(source.n, 'base64');
        }
        this.importFromObject(source);
        break;

      default:
        throw new LogicError(
          ErrorCode.SERVER,
          `Source ${format} must of type in `
          + `${JSON.stringify(PublicKey.allowedKeySources)}, not ${sourceType}`,
        );
    }
    if (this._rsaKey.getKeySize() !== keyConfig.size) {
      logger.debug(this._rsaKey.getKeySize());
      throw new LogicError(ErrorCode.KEY_SIZE);
    }

    const components = this._rsaKey.exportKey('components-public-der');
    this.components = {
      n: components.n[0] === 0
        ? components.n.slice(1)
        : components.n,
      e: components.e instanceof Buffer
        // FIXME: May be not Little Endian
        ? components.e.readUIntLE(0, components.e.length)
        : components.e,
    };
  }

  private importFromObject(obj: any) {
    if (!(
      typeof obj === 'object'
      && typeof obj.e === 'number'
      && (
        Array.isArray(obj.n)
        || obj.n instanceof Buffer
      )
    )) {
      throw new LogicError(ErrorCode.KEY_BAD);
    }
    if (keyConfig.size % 8 === 0) {
      obj.n = Buffer.concat([Buffer.alloc(1), Buffer.from(obj.n)]);
    }

    this._rsaKey.importKey(obj, 'components-public-der');
  }

  toString() {
    return this._rsaKey.exportKey('pkcs1-public-pem');
  }

  toBuffer() {
    return this._rsaKey.exportKey('pkcs1-public-der');
  }

  toJSON() {
    return {
      e: this.components.e,
      n: [...this.components.n.values()],
    };
  }
}

export function saveKeysForUser(
  userNameOrUser: string | User,
  serverKeys: RsaKeyPair,
  foreignPublicKey: PublicKey,
) {
  const user = typeof userNameOrUser === 'string'
    ? storage.get(userNameOrUser)
    : userNameOrUser;
  user.updateKeys(foreignPublicKey.toString(), serverKeys.privateKey);
  return user;
}
