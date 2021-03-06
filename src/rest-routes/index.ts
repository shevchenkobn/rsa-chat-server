import { Handler, Router } from 'express';
import { ErrorCode, LogicError } from '../services/errors.service';
import { authMiddlewares, createToken } from '../services/auth.service';
import { storage } from '../services/user-storage.service';
import { User } from '../services/user.class';
import { keyConfig } from '../config/config';
import { logger } from '../services/logger.service';
import {
  generateKeys,
  keyExpiration,
  PublicKey,
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

router.post('/key', ...authMiddlewares, (async (req, res, next) => {
  logger.log('Key generating');
  if (!(req.body instanceof Object)) {
    logger.log('Body is not object');
    next(new LogicError(ErrorCode.KEY_BAD));
    return;
  }

  let foreignPublicKey;
  try {
    foreignPublicKey = new PublicKey(req.body['public-key'], 'base64');
  } catch (err) {
    logger.error(err);
    if (err instanceof LogicError && err.code === ErrorCode.KEY_SIZE) {
      next(err);
    } else {
      next(new LogicError(ErrorCode.KEY_BAD));
    }
    return;
  }

  if (keyExpiration.has(req.user.name)) {
    keyExpiration.delete(req.user.name);
    logger.log('Had keys, deleting');
  }

  const rsaPair = await generateKeys();

  // logger.log(`My public key:\n${rsaPair.publicKey}`);
  // logger.log(`My private key:\n${rsaPair.privateKey}`);
  // logger.log(`Client's public key:\n${foreignPublicKey}`);

  saveKeysForUser(req.user, rsaPair, foreignPublicKey);
  // req.user.localPublicKey = rsaPair.publicKey;
  // req.user.remotePrivateKey = req.body['private-key'];
  // logger.log(`Client's private key:\n${req.user.remotePrivateKey}`);

  const myPubk = new PublicKey(rsaPair.publicKey, 'pkcs1-public-pem');
  logger.debug(`myPubK: ${myPubk.components.n.length}`);
  logger.debug(`forPubK: ${foreignPublicKey.components.n.length}`);
  res.json({
    'public-key': myPubk.toJSON(),
  });
}) as Handler);

/**
 * Chat
 */
// router.post('/chat', ...authMiddlewares, ((req, res, next) => {
//   // TODO: connect to chat
// }) as Handler);
