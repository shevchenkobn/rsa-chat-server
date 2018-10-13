import { ErrorCode, LogicError } from './errors.service';

export class User {
  readonly name: string;
  protected _encryptKey: string;
  protected _decryptKeys: string;
  protected _updatedAt: Date;

  get encryptKey() {
    if (this._encryptKey) {
      throw new LogicError(ErrorCode.KEY_BAD);
    }
    return this._encryptKey;
  }

  get decryptKeys() {
    if (this._decryptKeys) {
      throw new LogicError(ErrorCode.KEY_BAD);
    }
    return this._encryptKey;
  }

  get updatedAt() {
    return this._updatedAt;
  }

  constructor(name: string, encryptKey = '', decryptKey = '') {
    if (!name.trim()) {
      throw new LogicError(ErrorCode.AUTH_EMPTY_NAME);
    }
    this.name = name;
    this._encryptKey = encryptKey;
    this._decryptKeys = decryptKey;
    this._updatedAt = new Date();
  }

  hasKeys() {
    return !!this._encryptKey && !!this._decryptKeys;
  }

  updateKeys(encryptKey: string, decryptKey: string) {
    if (!encryptKey) {
      throw new LogicError(ErrorCode.KEY_BAD, 'Bad encrypt key');
    }
    if (!decryptKey) {
      throw new LogicError(ErrorCode.KEY_BAD, 'Bad decrypt key');
    }

    this._decryptKeys = decryptKey;
    this._encryptKey = encryptKey;
    this._updatedAt = new Date();

    return this._updatedAt;
  }

  deleteKeys() {
    this._decryptKeys = '';
    this._encryptKey = '';
    this._updatedAt = new Date();

    return this._updatedAt;
  }
}
