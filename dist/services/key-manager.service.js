"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const config_1 = require("../config/config");
const user_storage_service_1 = require("./user-storage.service");
const errors_service_1 = require("./errors.service");
const logger_service_1 = require("./logger.service");
function isNumericArray(arr) {
    return arr && arr.some && !arr.some(Number.isNaN);
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
        const specialCodes = [100];
        this._table = [[32, 0]];
        const start = frequentCharsCodes.length * 10 + 11;
        for (let i = 97; i < 123; i++) {
            const frequentCode = frequentCharsCodes.indexOf(i);
            if (frequentCode >= 0) {
                this._table.push([i, frequentCode + 1]);
            }
            else {
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
        throw new errors_service_1.LogicError(errors_service_1.ErrorCode.MSG_BAD, 'Invalid message'); // MSG_BAD
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
function finalizeDecode(message, outputEncoding = 'base64', trimEnd = true) {
    const decoded = Buffer.from(message);
    let j = 0;
    for (let i = 0; i < message.length; i++, j++) {
        let code = decoded[i];
        if (charTable.isOneDigitCode(code) || i === decoded.length - 1) {
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
    if (trimEnd) {
        const spaceCode = 32;
        for (; j - 1 >= 0 && decoded[j - 1] === spaceCode; j--)
            ;
    }
    return decoded.toString(outputEncoding, 0, j);
}
exports.finalizeDecode = finalizeDecode;
function encryptEncoded(msgBuffer, key, strictKey = false, fitToKey = true) {
    if (!isNumericArray(key)) {
        throw new TypeError('key is not numeric array');
    }
    const encrypted = Buffer.alloc(fitToKey
        ? key.length * Math.floor((msgBuffer.length - 1) / key.length + 1)
        : msgBuffer.length, 0);
    for (let i = 0; i < msgBuffer.length; i++) {
        encrypted[i] = msgBuffer[i];
    }
    if (strictKey && encrypted.length <= key.length) {
        throw new errors_service_1.LogicError(errors_service_1.ErrorCode.MSG_BAD, 'strictKey: message length exceeds key\'s');
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
        throw new errors_service_1.LogicError(errors_service_1.ErrorCode.MSG_BAD, 'strictKey: message length exceeds key\'s');
    }
    const decrypted = Buffer.from(msg);
    for (let i = 0; i < decrypted.length; i++) {
        decrypted[i] = (decrypted[i] + 10 - key[i % key.length]) % 10;
    }
    return decrypted;
}
exports.decryptEncoded = decryptEncoded;
function encrypt(msg, key, strictKey = false, inputEncoding = 'utf8', fitToKey = true) {
    return encryptEncoded(prepareEncode(msg, inputEncoding), key, strictKey, fitToKey);
}
exports.encrypt = encrypt;
function decrypt(msg, key, strictKey = false, outputEncoding = 'utf8', trimEnd = true) {
    return finalizeDecode(decryptEncoded(msg, key, strictKey), outputEncoding, trimEnd);
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
//# sourceMappingURL=key-manager.service.js.map