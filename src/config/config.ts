const keyByteSize = 256;

export const keyConfig = {
  type: 'rsa',
  size: keyByteSize,
  expireTime: 10 * 60 * 1000,
  keyFormat: {
    type: 'string',
    format: 'base64',
  },
};

export const jwtConfig = {
  secret: 'This is my rsa server',
};
