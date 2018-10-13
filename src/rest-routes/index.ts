import { Handler, Router } from 'express';
import { ErrorCode, LogicError } from '../services/errors.service';
import { authMiddlewares, createToken } from '../services/auth.service';
import { storage } from '../services/user-storage.service';
import { User } from '../services/user.class';
import { keyConfig } from '../config/config';
import { checkKeySize, generateKeys, saveKeysForUser } from '../services/key-manager.service';

export const router = Router();

/**
 * Authorization
 */
router.post('/auth', (req, res, next) => {
  if (
    typeof req.body !== 'object'
    || req.body.username !== 'string'
    || !req.body.username.trim()
  ) {
    throw new LogicError(ErrorCode.AUTH_EMPTY_NAME);
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
    typeof req.body !== 'object'
    || req.body['public-key'] !== 'string'
    || !req.body['public-key'].trim()
  ) {
    throw new LogicError(ErrorCode.KEY_BAD);
  }

  const foreignPublicKey: string = req.body['public-key'];
  if (!checkKeySize(foreignPublicKey)) {
    throw new LogicError(ErrorCode.KEY_SIZE);
  }
  const rsaPair = await generateKeys();

  saveKeysForUser(req.user, foreignPublicKey, rsaPair, true);

}) as Handler);

/**
 * Chat
 */
router.post('/chat', ...authMiddlewares, ((req, res, next) => {
  // TODO: connect to chat
}) as Handler);
