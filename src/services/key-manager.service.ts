// import * as crypto from 'crypto';
// import { privateDecrypt, publicEncrypt } from 'crypto';
// import * as RsaKey from 'node-rsa';
import { randomBytes } from 'crypto';
import { keyConfig } from '../config/config';
import { storage } from './user-storage.service';
import { ErrorCode, LogicError } from './errors.service';
import { User } from './user.class';
import { logger } from './logger.service';
// const CRYPTO_CONSTANTS: {[constant: string]: number} = (crypto as any).constants;

// const generateKeyPair = (crypto as any).generateKeyPair;
//
// const RSA_PADDING = new Map<number, number>([
//   [CRYPTO_CONSTANTS.RSA_PKCS1_PADDING, 11],
//   [CRYPTO_CONSTANTS.RSA_PKCS1_OAEP_PADDING, 41],
//   [CRYPTO_CONSTANTS.RSA_NO_PADDING, 0],
// ]);
//
// function getChunkSize(keyBits: number, type: number) {
//   const size = (keyBits / 8) >>> 0;
//   return size - RSA_PADDING.get(type)!;
// }
// const chunkSizes = [
//   getChunkSize(keyConfig.size, CRYPTO_CONSTANTS.RSA_PKCS1_PADDING),
//   getChunkSize(keyConfig.size, CRYPTO_CONSTANTS.RSA_NO_PADDING),
// ];
// logger.debug(chunkSizes);
//
// export interface RsaKeyPair {
//   publicKey: string;
//   privateKey: string;
// }
//
// export const generateKeyFormats = {
//   publicKeyEncoding: {
//     type: 'pkcs1',
//     format: 'pem',
//   },
//   privateKeyEncoding: {
//     type: 'pkcs1',
//     format: 'pem',
//   },
// };
//
// export function generateKeys(): Promise<RsaKeyPair> {
//   return new Promise((resolve, reject) => {
//     generateKeyPair(keyConfig.type, {
//       modulusLength: keyConfig.size,
//       ...generateKeyFormats,
//     }, (err: any | null | undefined, publicKey: string, privateKey: string) => {
//       if (err) {
//         reject(err);
//         return;
//       }
//       resolve({ publicKey, privateKey });
//     });
//   });
// }

// export function encrypt(key: string, buffer: Buffer) {
//   const buffers = [];
//   const [chunkSize] = chunkSizes;
//   logger.debug(buffer.length, chunkSize);
//   for (let i = 0; i < buffer.length; i += chunkSize) {
//     logger.debug(`${i} - ${i + chunkSize}`);
//     buffers.push(
//       publicEncrypt({
//         key,
//         padding: CRYPTO_CONSTANTS.RSA_PKCS1_PADDING,
//       }, buffer.slice(i, i + chunkSize)),
//     );
//   }
//   return Buffer.concat(buffers);
// }
//
// export function decrypt(key: string, buffer: Buffer) {
//   const buffers = [];
//   const [, chunkSize] = chunkSizes;
//   for (let i = 0; i < buffer.length; i += chunkSize) {
//     logger.debug(`${i} - ${i + chunkSize}`);
//     buffers.push(
//       privateDecrypt({
//         key,
//         padding: CRYPTO_CONSTANTS.RSA_PKCS1_PADDING,
//       }, buffer.slice(i, i + chunkSize)),
//     );
//   }
//   return Buffer.concat(buffers);
// }

export type NumericArray = number[]
  | Buffer
  | Int8Array
  | Uint8Array;

export function isNumericArray(arr: unknown): arr is NumericArray {
  return arr && (arr as any).some && (arr as any).some(Number.isNaN);
}

export async function getKey(size = keyConfig.size): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    randomBytes(size, (err, buf) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(normalizeKey(buf) as Buffer);
    });
  });
}

export function getNormalizedKey(key: NumericArray) {
  return (key as any).map((b: number) => b % 10);
}

export function normalizeKey(key: NumericArray) {
  for (let i = 0; i < key.length; i++) {
    key[i] %= 10;
  }
  return key;
}

const charTable = new class {
  private _table: [number, number][];
  private _oneDigitCodes: number[];

  constructor() {
    const frequentCharsCodes = [97, 116, 111, 110, 101, 115, 105, 114];
    const specialCodes = [100];
    this._table = [[32, 0]];

    const start = frequentCharsCodes.length * 10 + 11;
    for (let i = 97; i < 123; i++) {
      const frequentCode = frequentCharsCodes.indexOf(i);
      if (frequentCode >= 0) {
        this._table.push([i, frequentCode + 1]);
      } else {
        const frequentOffset = frequentCharsCodes.reduce((sum, c) => c < i ? sum + 1 : sum, 0);
        let code = start + i - 97 - frequentOffset;
        code += specialCodes.reduce((sum, c) => c <= code ? sum + 1 : sum, 0);
        this._table.push([i, code]);
      }
    }

    this._oneDigitCodes = this._table
      .filter(([char]) => frequentCharsCodes.includes(char))
      .map(([, code]) => code);
  }

  byChar(c: number) {
    const pair = this._table.find(v => v[0] === c);
    if (!pair) {
      throw new TypeError(`Invalid char: ${c}`);
    }
    return pair[1];
  }

  byCode(c: number) {
    const pair = this._table.find(v => v[1] === c);
    if (!pair) {
      throw new TypeError(`Invalid code: ${c}`);
    }
    return pair[0];
  }

  isOneDigitCode(code: number) {
    return this._oneDigitCodes.includes(code);
  }
};

const msgRegex = /^[a-z ]*$/;

export function prepareEncode(message: string, inputEncoding = 'utf8') {
  if (!msgRegex.test(message)) {
    throw new TypeError('Invalid message'); // MSG_BAD
  }

  const msgBuffer = Buffer.from(message, inputEncoding);

  const encoded: number[] = [];
  for (let i = 0, j = 0; i < msgBuffer.length; i++, j++) {
    const code = charTable.byChar(msgBuffer[i]);

    if (charTable.isOneDigitCode(code)) {
      encoded[j] = code;
    } else {
      encoded[j] = ~~(code % 100 / 10);
      j++;
      encoded[j] = code % 10;
    }
  }
  return encoded;
}

export function finalizeDecode(message: NumericArray, outputEncoding = 'base64') {
  const decoded = Buffer.from(message as Buffer);

  let j = 0;
  for (let i = 0; i < message.length; i++, j++) {
    let code = decoded[i];
    if (charTable.isOneDigitCode(code)) {
      decoded[j] = charTable.byCode(code);
    } else {
      i++;
      code = code * 10 + decoded[i];
      if (code <= 10 && code !== 0) {
        code += 100;
      }
      decoded[j] = charTable.byCode(code);
    }
  }
  return decoded.toString(outputEncoding, 0, j);
}

export function encryptEncoded(
  msgBuffer: NumericArray,
  key: NumericArray,
  strictKey = false,
) {
  if (!isNumericArray(key)) {
    throw new TypeError('key is not numeric array');
  }

  const encrypted = Buffer.from(msgBuffer as Buffer);

  if (strictKey && encrypted.length <= key.length) {
    throw new TypeError('strictKey: message length exceeds key\'s');
  }
  for (let i = 0; i < encrypted.length; i++) {
    encrypted[i] = (encrypted[i] + key[i % key.length]) % 10;
  }
  return encrypted;
}

export function decryptEncoded(msg: NumericArray, key: NumericArray, strictKey = false) {
  if (!isNumericArray(key)) {
    throw new TypeError('key is not numeric array');
  }
  if (strictKey && msg.length <= key.length) {
    throw new TypeError('strictKey: message length exceeds key\'s');
  }

  const decrypted = Buffer.from(msg as Buffer);
  for (let i = 0; i < decrypted.length; i++) {
    decrypted[i] = (decrypted[i] + 10 - key[i % key.length]) % 10;
  }
  return decrypted;
}

export function encrypt(msg: string, key: NumericArray, strictKey = false, inputEncoding = 'utf8') {
  return encryptEncoded(prepareEncode(msg, inputEncoding), key, strictKey);
}

export function decrypt(
  msg: NumericArray,
  key: NumericArray,
  strictKey = false,
  outputEncoding = 'utf8',
) {
  return finalizeDecode(decryptEncoded(msg, key, strictKey), outputEncoding);
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

// export class PublicKey {
//   static allowedKeySources: ReadonlyArray<string> = [
//     'string',
//     'object',
//   ];
//   static allowedKeyFormats: ReadonlyArray<string> = [
//     'pkcs1-public-der',
//     'pkcs1-public-pem',
//     'base64',
//   ];
//
//   readonly components: Readonly<{
//     e: number;
//     n: Buffer;
//   }>;
//   private _rsaKey: RsaKey;
//
//   constructor(source: any, format?: string) {
//     const sourceType = typeof source;
//     this._rsaKey = new RsaKey();
//     switch (sourceType) {
//       case 'string':
//         if (format === 'pkcs1-public-pem') {
//           this._rsaKey.importKey(source, format);
//         } else {
//           throw new LogicError(ErrorCode.SERVER, `Only pkcs1-public-pem is allowed, not ${format}`);
//         }
//         break;
//
//       case 'object':
//         if (format === 'pkcs1-public-der' && source instanceof Buffer) {
//           this._rsaKey.importKey(source, format);
//           break;
//         }
//         if (
//           typeof source.n === 'string'
//           && format === 'base64'
//         ) {
//           source.n = Buffer.from(source.n, 'base64');
//         }
//         this.importFromObject(source);
//         break;
//
//       default:
//         throw new LogicError(
//           ErrorCode.SERVER,
//           `Source ${format} must of type in `
//           + `${JSON.stringify(PublicKey.allowedKeySources)}, not ${sourceType}`,
//         );
//     }
//     if (this._rsaKey.getKeySize() !== keyConfig.size) {
//       logger.debug(this._rsaKey.getKeySize());
//       throw new LogicError(ErrorCode.KEY_SIZE);
//     }
//
//     const components = this._rsaKey.exportKey('components-public-der');
//     this.components = {
//       n: components.n[0] === 0
//         ? components.n.slice(1)
//         : components.n,
//       e: components.e instanceof Buffer
//         // FIXME: May be not Little Endian
//         ? components.e.readUIntLE(0, components.e.length)
//         : components.e,
//     };
//   }
//
//   private importFromObject(obj: any) {
//     if (!(
//       typeof obj === 'object'
//       && typeof obj.e === 'number'
//       && (
//         Array.isArray(obj.n)
//         || obj.n instanceof Buffer
//       )
//     )) {
//       throw new LogicError(ErrorCode.KEY_BAD);
//     }
//     if (keyConfig.size % 8 === 0) {
//       obj.n = Buffer.concat([Buffer.alloc(1), Buffer.from(obj.n)]);
//     }
//
//     this._rsaKey.importKey(obj, 'components-public-der');
//   }
//
//   toString() {
//     return this._rsaKey.exportKey('pkcs1-public-pem');
//   }
//
//   toBuffer() {
//     return this._rsaKey.exportKey('pkcs1-public-der');
//   }
//
//   toJSON() {
//     return {
//       e: this.components.e,
//       n: [...this.components.n.values()],
//     };
//   }
// }

// export function saveKeysForUser(
//   userNameOrUser: string | User,
//   serverKeys: RsaKeyPair,
//   foreignPublicKey: PublicKey,
// ) {
//   const user = typeof userNameOrUser === 'string'
//     ? storage.get(userNameOrUser)
//     : userNameOrUser;
//   user.updateKeys(foreignPublicKey.toString(), serverKeys.privateKey);
//   return user;
// }
