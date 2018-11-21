"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const keyByteSize = 8;
exports.keyConfig = {
    type: 'one-way-pad diffie-hellman',
    size: keyByteSize,
    expireTime: 10 * 60 * 1000,
    keyPaths: {
        GET: {
            response: {
                g: {
                    type: 'integer',
                    minimum: 2,
                },
                p: {
                    type: 'string',
                    format: 'utf8',
                },
            },
        },
        POST: {
            request: {
                bigB: {
                    type: 'string',
                    format: 'utf8',
                },
            },
            response: {
                bigA: {
                    type: 'string',
                    format: 'utf8',
                },
            },
        },
    },
};
exports.jwtConfig = {
    secret: 'This is my rsa server',
};
//# sourceMappingURL=config.js.map