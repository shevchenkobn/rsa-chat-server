"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.keyConfig = {
    type: 'rsa',
    size: 4096,
    expireTime: 10 * 60 * 1000,
    serverKey: {
        type: 'pkcs1',
        format: 'pem',
    },
};
exports.jwtConfig = {
    secret: 'This is my rsa server',
};
//# sourceMappingURL=config.js.map