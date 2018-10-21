"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const keyBitSize = 4096;
exports.keyConfig = {
    type: 'rsa',
    size: keyBitSize,
    expireTime: 10 * 60 * 1000,
    keyFormat: {
        type: 'components',
        format: {
            e: {
                type: 'integer',
                minimum: 0,
            },
            n: {
                type: 'array',
                items: {
                    type: 'integer',
                    minimum: 0,
                    maximum: 255,
                },
                minItems: keyBitSize,
                maxItems: keyBitSize,
            },
        },
    },
};
exports.jwtConfig = {
    secret: 'This is my rsa server',
};
//# sourceMappingURL=config.js.map