import * as crypto from 'crypto';
import { privateDecrypt, publicEncrypt } from 'crypto';
import { keyConfig } from 'src/config/config';
import { storage } from 'src/services/user-storage.service';
import { LogicError } from 'src/services/errors.service';
import { ErrorCode } from 'src/services/errors.service';
import { User } from 'src/services/user.class';
import { logger } from 'src/services/logger.service';
import { parseKey } from 'sshpk';

const { generateKeyPair } = crypto as any;
const chunkSizes = [getChunkSize(keyConfig.size), getChunkSize(keyConfig.size, false)];

function getChunkSize(keyBits: number, forSourceText = true) {
  const size = (keyBits / 8) >>> 0;
  return forSourceText ? size - 42 : size;
}

export interface RsaKey {
  publicKey: string;
  privateKey: string;
}

export function generateKeys(): Promise<RsaKey> {
  return new Promise((resolve, reject) => {
    generateKeyPair(keyConfig.type, {
      modulusLength: keyConfig.size,
      publicKeyEncoding: keyConfig.serverKey,
      privateKeyEncoding: keyConfig.serverKey,
    }, (err: any | null | undefined, publicKey: string, privateKey: string) => {
      if (err) {
        reject(err);
        return;
      }
      resolve({ publicKey, privateKey });
    });
  });
}

export function encrypt(key: string, str: string) {
  const buffers = [];
  const [chunkSize] = chunkSizes;
  for (let i = 0; i < str.length; i += chunkSize) {
    buffers.push(
      publicEncrypt(key, Buffer.from(str.substr(i, chunkSize))),
    );
  }
  return Buffer.concat(buffers);
}

export function decrypt(key: string, buffer: Buffer, encoding = 'utf8') {
  const buffers = [];
  const [, chunkSize] = chunkSizes;
  for (let i = 0; i < buffer.length; i += chunkSize) {
    buffers.push(
      privateDecrypt(key, buffer.slice(i, i + chunkSize)),
    );
  }
  return Buffer.concat(buffers).toString(encoding);
}

const scheduledExpirations = new Map<string, NodeJS.Timeout>();

function scheduleExpiration(userName: string) {
  if (scheduledExpirations.has(userName)) {
    throw new LogicError(ErrorCode.SERVER);
  }
  const timeout = setTimeout(() => {
    storage.get(userName).deleteKeys();
    scheduledExpirations.delete(userName);
    // FIXME: maybe not needed
    clearTimeout(timeout);
  }, keyConfig.expireTime);
}

storage.on('delete', (user: User) => {
  const timeout = scheduledExpirations.get(user.name);
  if (!timeout) {
    logger.warn(`No scheduled key removal for ${user}`);
    return;
  }

  clearTimeout(timeout);
  scheduledExpirations.delete(user.name);
});

export function saveKeysForUser(userName: string, serverKeys: RsaKey, foreignPublicKey: string) {
  if (parseKey(foreignPublicKey, 'auto').size !== keyConfig.size) {
    throw new LogicError(ErrorCode.KEY_SIZE);
  }

  const user = storage.get(userName);
  user.updateKeys(foreignPublicKey, serverKeys.privateKey);
  return user;
}
