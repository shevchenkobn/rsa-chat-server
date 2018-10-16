"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var ErrorCode;
(function (ErrorCode) {
    ErrorCode["SERVER"] = "SERVER";
    ErrorCode["AUTH_NO"] = "AUTH_NO";
    ErrorCode["AUTH_EMPTY_NAME"] = "AUTH_EMPTY_NAME";
    ErrorCode["AUTH_DUPLICATE_NAME"] = "AUTH_DUPLICATE_NAME";
    ErrorCode["KEY_BAD"] = "KEY_BAD";
    ErrorCode["KEY_SIZE"] = "KEY_SIZE";
    // WebSockets only
    ErrorCode["MSG_BAD"] = "MSG_BAD";
})(ErrorCode = exports.ErrorCode || (exports.ErrorCode = {}));
class LogicError extends Error {
    constructor(code, message = '') {
        super(message);
        this.code = code;
    }
}
exports.LogicError = LogicError;
// const obj = {
//     "type": "rsa",
//     "size": 4096,
//     "serverKey": {
//         "type": "pkcs1",
//         "format": "pem"
//     }
// };
//# sourceMappingURL=errors.service.js.map