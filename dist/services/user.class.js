"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const errors_service_1 = require("./errors.service");
class User {
    get encryptKey() {
        if (!this._encryptKey) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD);
        }
        return this._encryptKey;
    }
    get decryptKey() {
        if (!this._decryptKey) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD);
        }
        return this._decryptKey;
    }
    get updatedAt() {
        return this._updatedAt;
    }
    get lastLoggedIn() {
        return new Date(this._lastLoggedIn);
    }
    constructor(name, encryptKey = '', decryptKey = '') {
        if (!name.trim()) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_EMPTY_NAME);
        }
        this.name = name;
        this._encryptKey = encryptKey;
        this._decryptKey = decryptKey;
        this._updatedAt = Date.now();
        this._lastLoggedIn = this._updatedAt;
    }
    hasKeys() {
        return !!this._encryptKey && !!this._decryptKey;
    }
    updateKeys(encryptKey, decryptKey) {
        if (!encryptKey || !encryptKey.length) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD, 'Bad encrypt key');
        }
        if (!decryptKey || !encryptKey.length) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD, 'Bad decrypt key');
        }
        this._decryptKey = decryptKey;
        this._encryptKey = encryptKey;
        this._updatedAt = Date.now();
        return this._updatedAt;
    }
    deleteKeys() {
        this._decryptKey = '';
        this._encryptKey = '';
        this._updatedAt = Date.now();
        return this._updatedAt;
    }
    logIn() {
        this._lastLoggedIn = Date.now();
        return this._lastLoggedIn;
    }
}
exports.User = User;
//# sourceMappingURL=user.class.js.map