import { Handler, Router } from 'express';
import { ErrorCode, LogicError } from '../services/errors.service';
import { authMiddlewares, createToken } from '../services/auth.service';
import { storage } from '../services/user-storage.service';
import { User } from '../services/user.class';
import { keyConfig } from '../config/config';
import { logger } from '../services/logger.service';
import {
  getKey,
  encrypt,
  decrypt,
  isNumericArray, keyExpiration, normalizeKey,
} from '../services/key-manager.service';
import { DiffieHellman, pg as getPG } from '../services/diffie-hellman.service';
import { bufferEnsureLE } from '../services/helper.service';

export const router = Router();

/**
 * Ping
 */
router.get('/status', (req, res) => {
  res.status(200).json({});
});

/**
 * Authorization
 */
router.post('/auth', (req, res, next) => {
  if (
    !(req.body instanceof Object)
    || typeof req.body.username !== 'string'
    || !req.body.username.trim()
  ) {
    next(new LogicError(ErrorCode.AUTH_EMPTY_NAME));
    return;
  }

  const user = storage.add(req.body.username);
  const token = createToken(user);
  logger.log(`\nUser ${user.name} has token ${token}`);
  res.json({ token });
});

router.delete('/auth', ...authMiddlewares, ((req, res, next) => {
  const user: User = req.user;
  logger.log(`Deleting token for ${user.name}`);
  storage.delete(user.name);

  res.json({});
}) as Handler);

/**
 * Keys
 */
router.get('/key/info', (req, res) => {
  res.json(keyConfig);
});

router.get('/key', ...authMiddlewares, (async (req, res, next) => {
  logger.log('Key p and g requested');
  const pg = getPG();
  req.user.updateDiffieHellman(new DiffieHellman(pg.p, pg.g));

  res.json({
    p: bufferEnsureLE(Buffer.from(pg.p.toString(16), 'hex')).toString('base64'),
    g: Number(pg.g),
  });
}) as Handler);

router.post('/key', ...authMiddlewares, (async (req, res, next) => {
  logger.log('Key generating');
  if (!(req.body instanceof Object)) {
    logger.log('Body is not object');
    next(new LogicError(ErrorCode.KEY_BAD));
    return;
  }

  if (typeof req.body.bigB !== 'string') {
    next(new LogicError(ErrorCode.KEY_BAD));
    logger.error(`bad key: ${req.body['key']}`);
    return;
  }

  let bigA: bigint;
  const dh = req.user.diffieHellman;
  try {
    // const bigB = BigInt(`0x${
    //   bufferEnsureLE(Buffer.from(req.body.bigB, 'base64')).toString('hex')
    // }`);
    const bigB = BigInt(req.body.bigB);
    logger.log(`B: ${bigB}`);

    await dh.generateSmallA();
    dh.generateK(bigB);
    // bigA = Buffer.from(dh.getBigA().toString(16), 'hex');
    bigA = dh.getBigA();
    logger.log(`A: ${dh.getBigA()}`);
  } catch (err) {
    next(new LogicError(ErrorCode.KEY_BAD));
    logger.error(`${err};;; bad key: ${req.body['bigB']}`);
    return;
  }

  if (keyExpiration.has(req.user.name)) {
    keyExpiration.delete(req.user.name);
    logger.log('Had keys, deleting');
  }

  logger.log(`K: ${dh.k}`);
  const key = normalizeKey(Buffer.from(dh.k.toString(16), 'hex'));

  req.user.updateKeys(key, key);
  keyExpiration.schedule(req.user.name);

  res.json({
    // bigA: bufferEnsureLE(bigA).toString('base64'),
    bigA: bigA.toString(),
  });
}) as Handler);
