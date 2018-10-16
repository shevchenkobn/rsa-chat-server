"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const errors_service_1 = require("./errors.service");
const user_class_1 = require("./user.class");
const events_1 = require("events");
const map = new Map();
exports.storage = new class extends events_1.EventEmitter {
    has(name) {
        return map.has(name);
    }
    get(name) {
        const user = map.get(name);
        if (!user) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_NO, `Invalid name ${name}`);
        }
        return user;
    }
    add(name) {
        if (map.has(name)) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_DUPLICATE_NAME);
        }
        const user = new user_class_1.User(name);
        map.set(name, user);
        return user;
    }
    delete(nameOrUser) {
        const user = typeof nameOrUser === 'string'
            ? map.get(nameOrUser)
            : nameOrUser;
        if (!user) {
            throw new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_NO);
        }
        map.delete(user.name);
        this.emit('deleted', user);
        return user;
    }
};
//# sourceMappingURL=user-storage.service.js.map