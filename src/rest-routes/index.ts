import { Handler, Router } from 'express';
import { ErrorCode, LogicError } from '../services/errors.service';
import { authMiddlewares, createToken } from '../services/auth.service';
import { storage } from '../services/user-storage.service';
import { User } from '../services/user.class';
import { keyConfig } from '../config/config';
import { logger } from '../services/logger.service';
import {
  checkKeySize,
  generateKeys,
  keyExpiration,
  saveKeysForUser,
} from '../services/key-manager.service';

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
  res.json({ token });
});

router.delete('/auth', ...authMiddlewares, ((req, res, next) => {
  const user: User = req.user;
  storage.delete(user.name);

  res.json({});
}) as Handler);

/**
 * Keys
 */
router.get('/key/info', (req, res) => {
  res.json(keyConfig);
});

router.post('/key', ...authMiddlewares, (async (req, res, next) => {
  if (
    !(req.body instanceof Object)
    || req.body['public-key'] !== 'string'
    || !req.body['public-key'].trim()
  ) {
    next(new LogicError(ErrorCode.KEY_BAD));
    return;
  }

  const foreignPublicKey: string = req.body['public-key'];
  try {
    if (!checkKeySize(foreignPublicKey)) {
      next(new LogicError(ErrorCode.KEY_SIZE));
      return;
    }
  } catch (err) {
    logger.error(err);
    next(new LogicError(ErrorCode.KEY_BAD));
    return;
  }

  if (keyExpiration.has(req.user.name)) {
    keyExpiration.delete(req.user.name);
  }

  const rsaPair = await generateKeys();

  saveKeysForUser(req.user, foreignPublicKey, rsaPair, true);
}) as Handler);

/**
 * Chat
 */
// router.post('/chat', ...authMiddlewares, ((req, res, next) => {
//   // TODO: connect to chat
// }) as Handler);
