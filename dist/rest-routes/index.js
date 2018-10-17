"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const errors_service_1 = require("../services/errors.service");
const auth_service_1 = require("../services/auth.service");
const user_storage_service_1 = require("../services/user-storage.service");
const config_1 = require("../config/config");
const logger_service_1 = require("../services/logger.service");
const key_manager_service_1 = require("../services/key-manager.service");
exports.router = express_1.Router();
/**
 * Ping
 */
exports.router.get('/status', (req, res) => {
    res.status(200).json({});
});
/**
 * Authorization
 */
exports.router.post('/auth', (req, res, next) => {
    if (!(req.body instanceof Object)
        || typeof req.body.username !== 'string'
        || !req.body.username.trim()) {
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_EMPTY_NAME));
        return;
    }
    const user = user_storage_service_1.storage.add(req.body.username);
    const token = auth_service_1.createToken(user);
    res.json({ token });
});
exports.router.delete('/auth', ...auth_service_1.authMiddlewares, ((req, res, next) => {
    const user = req.user;
    user_storage_service_1.storage.delete(user.name);
    res.json({});
}));
/**
 * Keys
 */
exports.router.get('/key/info', (req, res) => {
    res.json(config_1.keyConfig);
});
exports.router.post('/key', ...auth_service_1.authMiddlewares, (async (req, res, next) => {
    if (!(req.body instanceof Object)
        || typeof req.body['public-key'] !== 'string'
        || !req.body['public-key'].trim()) {
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD));
        return;
    }
    const foreignPublicKey = req.body['public-key'];
    try {
        if (!key_manager_service_1.checkKeySize(foreignPublicKey)) {
            next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_SIZE));
            return;
        }
    }
    catch (err) {
        logger_service_1.logger.error(err);
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD));
        return;
    }
    if (key_manager_service_1.keyExpiration.has(req.user.name)) {
        key_manager_service_1.keyExpiration.delete(req.user.name);
    }
    const rsaPair = await key_manager_service_1.generateKeys();
    logger_service_1.logger.log(rsaPair);
    logger_service_1.logger.log(foreignPublicKey);
    key_manager_service_1.saveKeysForUser(req.user, foreignPublicKey, rsaPair, true);
    res.json({
        'public-key': rsaPair.publicKey,
    });
}));
/**
 * Chat
 */
// router.post('/chat', ...authMiddlewares, ((req, res, next) => {
//   // TODO: connect to chat
// }) as Handler);
//# sourceMappingURL=index.js.map