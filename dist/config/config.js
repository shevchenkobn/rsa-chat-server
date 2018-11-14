"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const keyByteSize = 256;
exports.keyConfig = {
    type: 'rsa',
    size: keyByteSize,
    expireTime: 10 * 60 * 1000,
    keyFormat: {
        type: 'string',
        format: 'base64',
    },
};
exports.jwtConfig = {
    secret: 'This is my rsa server',
};
//# sourceMappingURL=config.js.map