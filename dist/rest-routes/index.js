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
    if (!(req.body instanceof Object)
        || typeof req.body['public-key'] !== 'string'
        || !req.body['public-key'].trim()) {
        logger_service_1.logger.log('Bad object');
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
        logger_service_1.logger.log('Had keys, deleting');
    }
    const rsaPair = await key_manager_service_1.generateKeys();
    logger_service_1.logger.log(`My public key:\n${rsaPair.publicKey}`);
    logger_service_1.logger.log(`My private key:\n${rsaPair.privateKey}`);
    logger_service_1.logger.log(`Client's public key:\n${foreignPublicKey}`);
    key_manager_service_1.saveKeysForUser(req.user, foreignPublicKey, rsaPair, true);
    req.user.localPublicKey = rsaPair.publicKey;
    req.user.remotePrivateKey = req.body['private-key'];
    logger_service_1.logger.log(`Client's private key:\n${req.user.remotePrivateKey}`);
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