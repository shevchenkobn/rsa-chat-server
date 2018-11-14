"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// import * as crypto from 'crypto';
// import { privateDecrypt, publicEncrypt } from 'crypto';
// import * as RsaKey from 'node-rsa';
const crypto_1 = require("crypto");
const config_1 = require("../config/config");
const user_storage_service_1 = require("./user-storage.service");
const errors_service_1 = require("./errors.service");
const logger_service_1 = require("./logger.service");
function isNumericArray(arr) {
    return arr && arr.some && arr.some(Number.isNaN);
}
exports.isNumericArray = isNumericArray;
async function getKey(size = config_1.keyConfig.size) {
    return new Promise((resolve, reject) => {
        crypto_1.randomBytes(size, (err, buf) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(normalizeKey(buf));
        });
    });
}
exports.getKey = getKey;
function getNormalizedKey(key) {
    return key.map((b) => b % 10);
}
exports.getNormalizedKey = getNormalizedKey;
function normalizeKey(key) {
    for (let i = 0; i < key.length; i++) {
        key[i] %= 10;
    }
    return key;
}
exports.normalizeKey = normalizeKey;
const charTable = new class {
    constructor() {
        const frequentCharsCodes = [97, 116, 111, 110, 101, 115, 105, 114];
        this._table = [[32, 0]];
        const start = frequentCharsCodes.length * 10 + 11;
        for (let i = 97; i < 123; i++) {
            const frequentCode = frequentCharsCodes.indexOf(i);
            if (frequentCode >= 0) {
                this._table.push([i, frequentCode + 1]);
            }
            else {
                const frequentOffset = frequentCharsCodes.reduce((sum, c) => c < i ? sum + 1 : sum, 0);
                const code = start + i - 97 - frequentOffset % 100;
                this._table.push([i, code]);
            }
        }
        this._oneDigitCodes = this._table
            .filter(([char]) => frequentCharsCodes.includes(char)).map(([, code]) => code);
    }
    byChar(c) {
        const pair = this._table.find(v => v[0] === c);
        if (!pair) {
            throw new TypeError(`Invalid char: ${c}`);
        }
        return pair[1];
    }
    byCode(c) {
        const pair = this._table.find(v => v[1] === c);
        if (!pair) {
            throw new TypeError(`Invalid code: ${c}`);
        }
        return pair[0];
    }
    isOneDigitCode(code) {
        return this._oneDigitCodes.includes(code);
    }
};
const msgRegex = /^[a-z ]*$/;
function prepareEncode(message, inputEncoding = 'utf8') {
    if (!msgRegex.test(message)) {
        throw new TypeError('Invalid message'); // MSG_BAD
    }
    const msgBuffer = Buffer.from(message, inputEncoding);
    const encoded = [];
    for (let i = 0, j = 0; i < msgBuffer.length; i++, j++) {
        const code = charTable.byChar(msgBuffer[i]);
        if (charTable.isOneDigitCode(code)) {
            encoded[j] = code;
        }
        else {
            encoded[j] = ~~(code % 100 / 10);
            j++;
            encoded[j] = code % 10;
        }
    }
    return encoded;
}
exports.prepareEncode = prepareEncode;
function finalizeDecode(message, outputEncoding = 'base64') {
    const decoded = Buffer.from(message);
    let j = 0;
    for (let i = 0; i < message.length; i++, j++) {
        let code = decoded[i];
        if (charTable.isOneDigitCode(code)) {
            decoded[j] = charTable.byCode(code);
        }
        else {
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
exports.finalizeDecode = finalizeDecode;
function encryptEncoded(msgBuffer, key, strictKey = false) {
    if (!isNumericArray(key)) {
        throw new TypeError('key is not numeric array');
    }
    const encrypted = Buffer.from(msgBuffer);
    if (strictKey && encrypted.length <= key.length) {
        throw new TypeError('strictKey: message length exceeds key\'s');
    }
    for (let i = 0; i < encrypted.length; i++) {
        encrypted[i] = (encrypted[i] + key[i % key.length]) % 10;
    }
    return encrypted;
}
exports.encryptEncoded = encryptEncoded;
function decryptEncoded(msg, key, strictKey = false) {
    if (!isNumericArray(key)) {
        throw new TypeError('key is not numeric array');
    }
    if (strictKey && msg.length <= key.length) {
        throw new TypeError('strictKey: message length exceeds key\'s');
    }
    const decrypted = Buffer.from(msg);
    for (let i = 0; i < decrypted.length; i++) {
        decrypted[i] = (decrypted[i] + 10 - key[i % key.length]) % 10;
    }
    return decrypted;
}
exports.decryptEncoded = decryptEncoded;
function encrypt(msg, key, strictKey = false, inputEncoding = 'utf8') {
    return encryptEncoded(prepareEncode(msg, inputEncoding), key, strictKey);
}
exports.encrypt = encrypt;
function decrypt(msg, key, strictKey = false, outputEncoding = 'utf8') {
    return finalizeDecode(decryptEncoded(msg, key, strictKey), outputEncoding);
}
exports.decrypt = decrypt;
const scheduledExpirations = new Map();
exports.keyExpiration = {
    has(userName) {
        return scheduledExpirations.has(userName);
    },
    schedule(userName, callback) {
        if (scheduledExpirations.has(userName)) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.SERVER);
        }
        const timeout = setTimeout(() => {
            let error = null;
            let user = null;
            let timeout;
            let callback;
            try {
                user = user_storage_service_1.storage.get(userName);
                user.deleteKeys();
                [timeout, callback] = scheduledExpirations.get(userName);
                // FIXME: maybe not needed
                clearTimeout(timeout);
            }
            catch (err) {
                error = err;
            }
            if (callback) {
                callback(error, user);
            }
            scheduledExpirations.delete(userName);
        }, config_1.keyConfig.expireTime);
        scheduledExpirations.set(userName, [timeout, callback]);
    },
    delete(userName) {
        const scheduled = scheduledExpirations.get(userName);
        if (!scheduled) {
            logger_service_1.logger.warn(`No scheduled key removal for ${userName}`);
            return;
        }
        clearTimeout(scheduled[0]);
        scheduledExpirations.delete(userName);
    },
    hasCallback(userName) {
        const scheduled = scheduledExpirations.get(userName);
        return !!(scheduled && scheduled[1]);
    },
    setCallback(userName, callback) {
        const scheduled = scheduledExpirations.get(userName);
        if (!scheduled) {
            logger_service_1.logger.warn(`No scheduled key removal for ${userName}`);
            return;
        }
        scheduled[1] = callback;
    },
    deleteCallback(userName) {
        const scheduled = scheduledExpirations.get(userName);
        if (!scheduled) {
            logger_service_1.logger.warn(`No scheduled key removal for ${userName}`);
            return;
        }
        scheduled[1] = undefined;
    },
};
user_storage_service_1.storage.on('deleted', (user) => {
    exports.keyExpiration.delete(user.name);
    logger_service_1.logger.log(`keyExpiration for ${user.name} is deleted`);
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
//# sourceMappingURL=key-manager.service.js.map