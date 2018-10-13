export enum ErrorCode {
    SERVER = 'SERVER',

    AUTH_NO = 'AUTH_NO',
    AUTH_EMPTY_NAME = 'AUTH_EMPTY_NAME',
    AUTH_DUPLICATE_NAME = 'AUTH_DUPLICATE_NAME',

    KEY_BAD = 'KEY_BAD',
    KEY_SIZE = 'KEY_SIZE',
}

export class LogicError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message = '') {
    super(message);
    this.code = code;
  }
}

// const obj = {
//     "type": "rsa",
//     "size": 4096,
//     "serverKey": {
//         "type": "pkcs1",
//         "format": "pem"
//     }
// };
