"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jwt = require("jsonwebtoken");
const jsonwebtoken_1 = require("jsonwebtoken");
const config_1 = require("../config/config");
const user_storage_service_1 = require("./user-storage.service");
const expressJwt = require("express-jwt");
const errors_service_1 = require("./errors.service");
const logger_service_1 = require("./logger.service");
function createToken(user) {
    return jwt.sign({ id: user.name }, config_1.jwtConfig.secret);
}
exports.createToken = createToken;
function getUserFromPayload(obj) {
    if (!(obj instanceof Object) || !('id' in obj)) {
        throw new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_NO);
    }
    const name = obj.id;
    return user_storage_service_1.storage.get(name);
}
exports.getUserFromPayload = getUserFromPayload;
exports.authMiddlewares = [
    expressJwt({ secret: config_1.jwtConfig.secret }),
    (err, req, res, next) => {
        logger_service_1.logger.error(err);
        res.status(401).json(new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_NO));
    },
    ((req, res, next) => {
        req.user = getUserFromPayload(req.user);
        logger_service_1.logger.log(`User: ${req.user.name}`);
        next();
    }),
];
const tokenSchemeRegex = /^Bearer$/;
const spaces = /\s+/;
function getJWTPayload(httpReq) {
    const authParts = httpReq.headers.authorization
        .split(spaces);
    if (authParts.length !== 2 || !tokenSchemeRegex.test(authParts[0])) {
        return null;
    }
    let payload;
    try {
        payload = jsonwebtoken_1.verify(authParts[1], config_1.jwtConfig.secret);
    }
    catch (err) {
        logger_service_1.logger.error(err);
        return null;
    }
    return payload;
}
function getUserFromHTTPRequest(request) {
    const payload = getJWTPayload(request);
    if (payload instanceof Object && typeof payload.id === 'string') {
        return user_storage_service_1.storage.get(payload.id);
    }
    throw new errors_service_1.LogicError(errors_service_1.ErrorCode.AUTH_NO);
}
exports.getUserFromHTTPRequest = getUserFromHTTPRequest;
//# sourceMappingURL=auth.service.js.map