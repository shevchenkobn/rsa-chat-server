"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const crypto_1 = require("crypto");
const config_1 = require("../config/config");
const user_storage_service_1 = require("./user-storage.service");
const errors_service_1 = require("./errors.service");
const errors_service_2 = require("./errors.service");
const logger_service_1 = require("./logger.service");
const sshpk_1 = require("sshpk");
const generateKeyPair = crypto.generateKeyPair;
const chunkSizes = [getChunkSize(config_1.keyConfig.size), getChunkSize(config_1.keyConfig.size, false)];
function getChunkSize(keyBits, forSourceText = true) {
    const size = (keyBits / 8) >>> 0;
    return forSourceText ? size - 42 : size;
}
function generateKeys() {
    return new Promise((resolve, reject) => {
        generateKeyPair(config_1.keyConfig.type, {
            modulusLength: config_1.keyConfig.size,
            publicKeyEncoding: config_1.keyConfig.serverKey,
            privateKeyEncoding: config_1.keyConfig.serverKey,
        }, (err, publicKey, privateKey) => {
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
            throw new errors_service_1.LogicError(errors_service_2.ErrorCode.SERVER);
        }
        const timeout = setTimeout(() => {
            const user = user_storage_service_1.storage.get(userName);
            user.deleteKeys();
            const [timeout, callback] = scheduledExpirations.get(userName);
            // FIXME: maybe not needed
            clearTimeout(timeout);
            if (callback) {
                callback(user);
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
user_storage_service_1.storage.on('delete', (user) => exports.keyExpiration.delete(user.name));
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
function checkKeySize(key) {
    return sshpk_1.parseKey(key, 'auto').size !== config_1.keyConfig.size;
}
exports.checkKeySize = checkKeySize;
function saveKeysForUser(userNameOrUser, foreignPublicKey, serverKeys, foreignChecked = false) {
    if (!foreignChecked
        && sshpk_1.parseKey(foreignPublicKey, 'auto').size !== config_1.keyConfig.size) {
        throw new errors_service_1.LogicError(errors_service_2.ErrorCode.KEY_SIZE);
    }
    const user = typeof userNameOrUser === 'string'
        ? user_storage_service_1.storage.get(userNameOrUser)
        : userNameOrUser;
    user.updateKeys(foreignPublicKey, serverKeys.privateKey);
    return user;
}
exports.saveKeysForUser = saveKeysForUser;
//# sourceMappingURL=key-manager.service.js.map