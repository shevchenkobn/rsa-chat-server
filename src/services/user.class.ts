import { ErrorCode, LogicError } from './errors.service';

export class User {
  readonly name: string;
  protected _encryptKey: string;
  protected _decryptKey: string;
  protected _updatedAt: number;
  protected _lastLoggedIn: number;

  get encryptKey() {
    if (!this._encryptKey) {
      throw new LogicError(ErrorCode.KEY_BAD);
    }
    return this._encryptKey;
  }

  get decryptKey() {
    if (!this._decryptKey) {
      throw new LogicError(ErrorCode.KEY_BAD);
    }
    return this._decryptKey;
  }

  get updatedAt() {
    return this._updatedAt;
  }

  get lastLoggedIn() {
    return new Date(this._lastLoggedIn);
  }

  constructor(name: string, encryptKey = '', decryptKey = '') {
    if (!name.trim()) {
      throw new LogicError(ErrorCode.AUTH_EMPTY_NAME);
    }
    this.name = name;
    this._encryptKey = encryptKey;
    this._decryptKey = decryptKey;
    this._updatedAt = Date.now();
    this._lastLoggedIn = this._updatedAt;
  }

  hasKeys() {
    return !!this._encryptKey && !!this._decryptKey;
  }

  updateKeys(encryptKey: string, decryptKey: string) {
    if (!encryptKey) {
      throw new LogicError(ErrorCode.KEY_BAD, 'Bad encrypt key');
    }
    if (!decryptKey) {
      throw new LogicError(ErrorCode.KEY_BAD, 'Bad decrypt key');
    }

    this._decryptKey = decryptKey;
    this._encryptKey = encryptKey;
    this._updatedAt = Date.now();

    return this._updatedAt;
  }

  deleteKeys() {
    this._decryptKey = '';
    this._encryptKey = '';
    this._updatedAt = Date.now();

    return this._updatedAt;
  }

  logIn() {
    this._lastLoggedIn = Date.now();
    return this._lastLoggedIn;
  }
}
