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
    logger_service_1.logger.log(`\nUser ${user.name} has token ${token}`);
    res.json({ token });
});
exports.router.delete('/auth', ...auth_service_1.authMiddlewares, ((req, res, next) => {
    const user = req.user;
    logger_service_1.logger.log(`Deleting token for ${user.name}`);
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
    logger_service_1.logger.log('Key generating');
    if (!(req.body instanceof Object)) {
        logger_service_1.logger.log('Body is not object');
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD));
        return;
    }
    if (typeof req.body.key !== 'string') {
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD));
        logger_service_1.logger.error(`bad key: ${req.body['key']}`);
        return;
    }
    let clientKey;
    try {
        clientKey = key_manager_service_1.normalizeKey(Buffer.from(req.body.key, config_1.keyConfig.keyFormat.format));
    }
    catch (err) {
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD));
        logger_service_1.logger.error(`bad key: ${req.body['key']}`);
        return;
    }
    if (req.body.key.length === config_1.keyConfig.size) {
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_SIZE));
        logger_service_1.logger.error(`bad key size: ${clientKey}`);
        return;
    }
    if (key_manager_service_1.keyExpiration.has(req.user.name)) {
        key_manager_service_1.keyExpiration.delete(req.user.name);
        logger_service_1.logger.log('Had keys, deleting');
    }
    const serverKey = await key_manager_service_1.getKey();
    // logger.log(`My public key:\n${rsaPair.publicKey}`);
    // logger.log(`My private key:\n${rsaPair.privateKey}`);
    // logger.log(`Client's public key:\n${clientKey}`);
    // req.user.localPublicKey = rsaPair.publicKey;
    // req.user.remotePrivateKey = req.body['private-key'];
    // logger.log(`Client's private key:\n${req.user.remotePrivateKey}`);
    req.user.updateKeys(clientKey, serverKey);
    res.json({
        key: serverKey.toString('base64'),
    });
}));
/**
 * Chat
 */
// router.post('/chat', ...authMiddlewares, ((req, res, next) => {
//   // TODO: connect to chat
// }) as Handler);
//# sourceMappingURL=index.js.map