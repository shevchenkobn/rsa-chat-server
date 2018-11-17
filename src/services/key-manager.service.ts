import { randomBytes } from 'crypto';
import { keyConfig } from '../config/config';
import { storage } from './user-storage.service';
import { ErrorCode, LogicError } from './errors.service';
import { User } from './user.class';
import { logger } from './logger.service';

export type NumericArray = number[]
  | Buffer
  | Int8Array
  | Uint8Array;

export function isNumericArray(arr: unknown): arr is NumericArray {
  return arr && (arr as any).some && !(arr as any).some(Number.isNaN);
}

export async function getKey(size = keyConfig.size): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
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
    throw new LogicError(ErrorCode.MSG_BAD, 'Invalid message'); // MSG_BAD
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

export function finalizeDecode(message: NumericArray, outputEncoding = 'base64', trimEnd = true) {
  const decoded = Buffer.from(message as Buffer);

  let j = 0;
  for (let i = 0; i < message.length; i++, j++) {
    let code = decoded[i];
    if (charTable.isOneDigitCode(code) || i === decoded.length - 1) {
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
  if (trimEnd) {
    const spaceCode = 32;
    for (; j - 1 >= 0 && decoded[j - 1] === spaceCode; j--);
  }
  return decoded.toString(outputEncoding, 0, j);
}

export function encryptEncoded(
  msgBuffer: NumericArray,
  key: NumericArray,
  strictKey = false,
  fitToKey = true,
) {
  if (!isNumericArray(key)) {
    throw new TypeError('key is not numeric array');
  }

  const encrypted = Buffer.alloc(
    fitToKey
      ? key.length * Math.floor((msgBuffer.length - 1) / key.length + 1)
      : msgBuffer.length,
    0,
  );
  for (let i = 0; i < msgBuffer.length; i++) {
    encrypted[i] = msgBuffer[i];
  }

  if (strictKey && encrypted.length <= key.length) {
    throw new LogicError(ErrorCode.MSG_BAD, 'strictKey: message length exceeds key\'s');
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
    throw new LogicError(ErrorCode.MSG_BAD, 'strictKey: message length exceeds key\'s');
  }

  const decrypted = Buffer.from(msg as Buffer);
  for (let i = 0; i < decrypted.length; i++) {
    decrypted[i] = (decrypted[i] + 10 - key[i % key.length]) % 10;
  }
  return decrypted;
}

export function encrypt(
  msg: string,
  key: NumericArray,
  strictKey = false,
  inputEncoding = 'utf8',
  fitToKey = true,
) {
  return encryptEncoded(prepareEncode(msg, inputEncoding), key, strictKey, fitToKey);
}

export function decrypt(
  msg: NumericArray,
  key: NumericArray,
  strictKey = false,
  outputEncoding = 'utf8',
  trimEnd = true,
) {
  return finalizeDecode(decryptEncoded(msg, key, strictKey), outputEncoding, trimEnd);
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
