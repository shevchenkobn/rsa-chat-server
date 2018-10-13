export const keyConfig = {
  type: 'rsa',
  size: 4096,
  expireTime: 10 * 60 * 1000,
  serverKey: {
    type: 'pkcs1',
    format: 'pem',
  },
};
