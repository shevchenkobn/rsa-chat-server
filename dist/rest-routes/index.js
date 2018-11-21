"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const errors_service_1 = require("../services/errors.service");
const auth_service_1 = require("../services/auth.service");
const user_storage_service_1 = require("../services/user-storage.service");
const config_1 = require("../config/config");
const logger_service_1 = require("../services/logger.service");
const key_manager_service_1 = require("../services/key-manager.service");
const diffie_hellman_service_1 = require("../services/diffie-hellman.service");
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
exports.router.get('/key', ...auth_service_1.authMiddlewares, (async (req, res, next) => {
    logger_service_1.logger.log('Key p and g requested');
    const pg = diffie_hellman_service_1.pg();
    req.user.updateDiffieHellman(new diffie_hellman_service_1.DiffieHellman(pg.p, pg.g));
    res.json({
        p: Buffer.from(pg.p.toString(16), 'hex').toString('base64'),
        g: Number(pg.g),
    });
}));
exports.router.post('/key', ...auth_service_1.authMiddlewares, (async (req, res, next) => {
    logger_service_1.logger.log('Key generating');
    if (!(req.body instanceof Object)) {
        logger_service_1.logger.log('Body is not object');
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD));
        return;
    }
    logger_service_1.logger.debug('Body is object');
    if (typeof req.body.bigB !== 'string') {
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD));
        logger_service_1.logger.error(`bad key: ${req.body['key']}`);
        return;
    }
    logger_service_1.logger.debug('Body has bigB');
    let bigA;
    const dh = req.user.diffieHellman;
    try {
        const bigB = BigInt(`0x${Buffer.from(req.body.bigB, 'base64').toString('hex')}`);
        logger_service_1.logger.debug('bigB was converted');
        await dh.generateSmallA();
        logger_service_1.logger.debug('smallA was generated');
        dh.generateK(bigB);
        logger_service_1.logger.debug('K is calculated');
        bigA = Buffer.from(dh.getBigA().toString(16), 'hex');
        logger_service_1.logger.log(`A: ${dh.getBigA()}`);
    }
    catch (err) {
        next(new errors_service_1.LogicError(errors_service_1.ErrorCode.KEY_BAD));
        logger_service_1.logger.error(`${err};;; bad key: ${req.body['bigB']}`);
        return;
    }
    if (key_manager_service_1.keyExpiration.has(req.user.name)) {
        key_manager_service_1.keyExpiration.delete(req.user.name);
        logger_service_1.logger.log('Had keys, deleting');
    }
    logger_service_1.logger.log(`K: ${dh.k}`);
    const key = key_manager_service_1.normalizeKey(Buffer.from(dh.k.toString(16), 'hex'));
    logger_service_1.logger.debug('K is normalized: ' + key.join(', '));
    req.user.updateKeys(key, key);
    key_manager_service_1.keyExpiration.schedule(req.user.name);
    res.json({
        bigA: bigA.toString('base64'),
    });
}));
//# sourceMappingURL=index.js.map