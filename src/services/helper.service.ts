import { endianness } from 'os';

const isLittleEndian = endianness() === 'LE';

export function bufferEnsureLE(buf: Buffer) {
  if (isLittleEndian) {
    return buf;
  }
  const half = buf.length / 2;
  const last = buf.length - 1;
  for (let i = 0; i < half; i++) {
    const t = buf[i];
    buf[i] = buf[last - i];
    buf[last - i] = t;
  }
  return buf;
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint) {
  if (exponent < 0n) {
    throw new TypeError(`Negative exponent: ${exponent}`);
  }
  if (base === 0n || modulus === 0n || modulus === 1n) {
    return 0n;
  }
  if (exponent === 0n) {
    return 1n;
  }
  let e = exponent;
  let b = base;
  let result = 1n;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % modulus;
    }
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}