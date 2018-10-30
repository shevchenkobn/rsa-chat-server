"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const crypto_1 = require("crypto");
const RsaKey = require("node-rsa");
const config_1 = require("../config/config");
const user_storage_service_1 = require("./user-storage.service");
const errors_service_1 = require("./errors.service");
const logger_service_1 = require("./logger.service");
const CRYPTO_CONSTANTS = crypto.constants;
const generateKeyPair = crypto.generateKeyPair;
const RSA_PADDING = new Map([
    [CRYPTO_CONSTANTS.RSA_PKCS1_PADDING, 11],
    [CRYPTO_CONSTANTS.RSA_PKCS1_OAEP_PADDING, 41],
    [CRYPTO_CONSTANTS.RSA_NO_PADDING, 0],
]);
function getChunkSize(keyBits, type) {
    const size = (keyBits / 8) >>> 0;
    return size - RSA_PADDING.get(type);
}
const chunkSizes = [
    getChunkSize(config_1.keyConfig.size, CRYPTO_CONSTANTS.RSA_PKCS1_PADDING),
    getChunkSize(config_1.keyConfig.size, CRYPTO_CONSTANTS.RSA_NO_PADDING),
];
logger_service_1.logger.debug(chunkSizes);
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
    logger_service_1.logger.debug(buffer.length, chunkSize);
    for (let i = 0; i < buffer.length; i += chunkSize) {
        logger_service_1.logger.debug(`${i} - ${i + chunkSize}`);
        buffers.push(crypto_1.publicEncrypt({
            key,
            padding: CRYPTO_CONSTANTS.RSA_PKCS1_PADDING,
        }, buffer.slice(i, i + chunkSize)));
    }
    return Buffer.concat(buffers);
}
exports.encrypt = encrypt;
function decrypt(key, buffer) {
    const buffers = [];
    const [, chunkSize] = chunkSizes;
    for (let i = 0; i < buffer.length; i += chunkSize) {
        buffers.push(crypto_1.privateDecrypt({
            key,
            padding: CRYPTO_CONSTANTS.RSA_PKCS1_PADDING,
        }, buffer.slice(i, i + chunkSize)));
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
                if (format === 'pkcs1-public-der' && source instanceof Buffer) {
                    this._rsaKey.importKey(source, format);
                    break;
                }
                if (typeof source.n === 'string'
                    && format === 'base64') {
                    source.n = Buffer.from(source.n, 'base64');
                }
                this.importFromObject(source);
                break;
            default:
                throw new errors_service_1.LogicError(errors_service_1.ErrorCode.SERVER, `Source ${format} must of type in `
                    + `${JSON.stringify(PublicKey.allowedKeySources)}, not ${sourceType}`);
        }
        if (this._rsaKey.getKeySize() !== config_1.keyConfig.size) {
            logger_service_1.logger.debug(this._rsaKey.getKeySize());
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_SIZE);
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
    importFromObject(obj) {
        if (!(typeof obj === 'object'
            && typeof obj.e === 'number'
            && (Array.isArray(obj.n)
                || obj.n instanceof Buffer))) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD);
        }
        if (config_1.keyConfig.size % 8 === 0) {
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
PublicKey.allowedKeySources = [
    'string',
    'object',
];
PublicKey.allowedKeyFormats = [
    'pkcs1-public-der',
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