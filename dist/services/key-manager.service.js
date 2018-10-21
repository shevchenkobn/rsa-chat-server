"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const crypto_1 = require("crypto");
const RsaKey = require("node-rsa");
const config_1 = require("../config/config");
const user_storage_service_1 = require("./user-storage.service");
const errors_service_1 = require("./errors.service");
const logger_service_1 = require("./logger.service");
const generateKeyPair = crypto.generateKeyPair;
const chunkSizes = [getChunkSize(config_1.keyConfig.size), getChunkSize(config_1.keyConfig.size, false)];
function getChunkSize(keyBits, forSourceText = true) {
    const size = (keyBits / 8) >>> 0;
    return forSourceText ? size - 42 : size;
}
exports.generateKeyFormats = {
    publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
    },
    privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
    },
};
function generateKeys() {
    return new Promise((resolve, reject) => {
        generateKeyPair(config_1.keyConfig.type, Object.assign({ modulusLength: config_1.keyConfig.size }, exports.generateKeyFormats), (err, publicKey, privateKey) => {
            if (err) {
                reject(err);
                return;
            }
            resolve({ publicKey, privateKey });
        });
    });
}
exports.generateKeys = generateKeys;
function encrypt(key, buffer) {
    const buffers = [];
    const [chunkSize] = chunkSizes;
    for (let i = 0; i < buffer.length; i += chunkSize) {
        buffers.push(crypto_1.publicEncrypt(key, buffer.slice(i, i + chunkSize)));
    }
    return Buffer.concat(buffers);
}
exports.encrypt = encrypt;
function decrypt(key, buffer) {
    const buffers = [];
    const [, chunkSize] = chunkSizes;
    for (let i = 0; i < buffer.length; i += chunkSize) {
        buffers.push(crypto_1.privateDecrypt(key, buffer.slice(i, i + chunkSize)));
    }
    return Buffer.concat(buffers);
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
// export function scheduleExpiration(userName: string, callback?: KeyExpiredCallback) {
//   if (scheduledExpirations.has(userName)) {
//     throw new LogicError(ErrorCode.SERVER);
//   }
//   const timeout = setTimeout(() => {
//     const user = storage.get(userName);
//     user.deleteKeys();
//     scheduledExpirations.delete(userName);
//     // FIXME: maybe not needed
//     clearTimeout(timeout);
//
//     const callback = scheduledExpirations.get(userName)![1];
//     if (callback) {
//       callback(user);
//     }
//   }, keyConfig.expireTime);
//   scheduledExpirations.set(userName, [timeout, callback]);
// }
//
// export function setExpirationCallback(userName: string, callback?: KeyExpiredCallback) {
//   const scheduled = scheduledExpirations.get(userName);
//   if (!scheduled) {
//     logger.warn(`No scheduled key removal for ${userName}`);
//     return;
//   }
//
//   scheduled[1] = callback;
// }
class PublicKey {
    constructor(source, format) {
        const sourceType = typeof source;
        this._rsaKey = new RsaKey();
        switch (sourceType) {
            case 'string':
                if (format === 'pkcs1-public-pem') {
                    this._rsaKey.importKey(source, format);
                }
                else {
                    throw new errors_service_1.LogicError(errors_service_1.ErrorCode.SERVER, `Only pkcs1-public-pem is allowed, not ${format}`);
                }
                break;
            case 'object':
                if (format === 'base64') {
                    source.n = JSON.parse(Buffer.from(source.n).toString('utf8'));
                }
                this.importFromObject(source);
                break;
            default:
                throw new errors_service_1.LogicError(errors_service_1.ErrorCode.SERVER, `Source ${format} must of type in `
                    + `${JSON.stringify(PublicKey.allowedKeySources)}, not ${sourceType}`);
        }
        if (this._rsaKey.getKeySize() !== config_1.keyConfig.size) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_SIZE);
        }
        const components = this._rsaKey.exportKey('components-public-der');
        this.components = {
            n: components.n,
            e: components.e instanceof Buffer
                // FIXME: May be not Little Endian
                ? components.e.readUIntLE(0, components.e.length)
                : components.e,
        };
    }
    importFromObject(obj) {
        if (!(typeof obj === 'object'
            && typeof obj.e === 'number'
            && (Array.isArray(obj.n)
                || obj.n instanceof Buffer))) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD);
        }
        this._rsaKey.importKey(obj, 'components-public');
    }
    toString() {
        return this._rsaKey.exportKey('pkcs1-public-pem');
    }
    toJSON() {
        return {
            e: this.components,
            n: [...this.components.n.values()],
        };
    }
}
PublicKey.allowedKeySources = [
    'string',
    'object',
];
PublicKey.allowedKeyFormats = [
    'pkcs1-public-pem',
    'base64',
];
exports.PublicKey = PublicKey;
function saveKeysForUser(userNameOrUser, serverKeys, foreignPublicKey) {
    const user = typeof userNameOrUser === 'string'
        ? user_storage_service_1.storage.get(userNameOrUser)
        : userNameOrUser;
    user.updateKeys(foreignPublicKey.toString(), serverKeys.privateKey);
    return user;
}
exports.saveKeysForUser = saveKeysForUser;
//# sourceMappingURL=key-manager.service.js.map