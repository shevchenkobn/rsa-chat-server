import { ErrorCode, LogicError } from './errors.service';
import { NumericArray } from './key-manager.service';
import { DiffieHellman } from './diffie-hellman.service';

export class User {
  readonly name: string;
  protected _encryptKey: NumericArray | null;
  protected _decryptKey: NumericArray | null;
  protected _diffieHellman: DiffieHellman | null = null;
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

  get diffieHellman() {
    return this._diffieHellman;
  }

  constructor(name: string, encryptKey = null, decryptKey = null) {
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

  updateDiffieHellman(dh: DiffieHellman) {
    if(!dh) {
      throw new TypeError(`diffieHellman is invalid: ${dh}`);
    }
    this._diffieHellman = dh;
  }

  deleteDiffieHellman() {
    this._diffieHellman = null;
  }

  updateKeys(encryptKey: NumericArray, decryptKey: NumericArray) {
    if (!encryptKey || !encryptKey.length) {
      throw new LogicError(ErrorCode.KEY_BAD, 'Bad encrypt key');
    }
    if (!decryptKey || !decryptKey.length) {
      throw new LogicError(ErrorCode.KEY_BAD, 'Bad decrypt key');
    }

    this._decryptKey = decryptKey;
    this._encryptKey = encryptKey;
    this._updatedAt = Date.now();

    return this._updatedAt;
  }

  deleteKeys() {
    this._decryptKey = null;
    this._encryptKey = null;
    this._updatedAt = Date.now();

    return this._updatedAt;
  }

  logIn() {
    this._lastLoggedIn = Date.now();
    return this._lastLoggedIn;
  }
}
