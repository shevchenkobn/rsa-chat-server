"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const config_1 = require("../config/config");
const bytes = 332 / 8;
const primeBitLength = config_1.keyConfig.size * 8;
class DiffieHellman {
    constructor(p, g) {
        this._a = 0n;
        this._bigA = 0n;
        this._bigB = 0n;
        this._k = 0n;
        if (p <= 0n) {
            throw new TypeError(`p: ${p} is invalid`);
        }
        if (g <= 0n) {
            throw new TypeError(`g: ${g} is invalid`);
        }
        this._p = p;
        this._g = g;
    }
    get hasSmallA() {
        return this._a !== 0n;
    }
    get hasK() {
        return this._k !== 0n;
    }
    get k() {
        if (this._k === 0n) {
            throw new TypeError('k is not initialized');
        }
        return this._k;
    }
    generateSmallA() {
        return new Promise((resolve, reject) => {
            crypto_1.randomBytes(bytes, (err, buf) => {
                if (err) {
                    reject(err);
                    return;
                }
                logger_service_1.logger.debug('smallA successfully generated');
                this._a = BigInt(`0x${buf.toString('hex')}`);
                resolve(this._a);
            });
        });
    }
    getBigA() {
        if (this._a === 0n) {
            throw new TypeError('a is not defined');
        }
        if (!this._bigA) {
            this._bigA = helper_service_1.modPow(this._g, this._a, this._p);
        }
        return this._bigA;
    }
    generateK(bigB) {
        if (this._k) {
            throw new TypeError('K is ready');
        }
        this._bigB = bigB;
        this._k = helper_service_1.modPow(bigB, this._a, this._p);
        return this._k;
    }
}
exports.DiffieHellman = DiffieHellman;
function getPG() {
    const p = getPrime();
    return {
        p,
        g: getPrimitiveRoot(p),
    };
}
exports.getPG = getPG;
function getPrime() {
    let prime;
    do {
        prime = getRandom();
    } while (!isPrime(prime));
    return prime;
}
// helpers for getPrime
function getRandom() {
    return Math.random() * Number.MAX_SAFE_INTEGER;
}
function isPrime(n) {
    if (n <= 1) {
        return false;
    }
    if (n <= 3) {
        return true;
    }
    if (n % 2 === 0 || n % 3 === 0) {
        return false;
    }
    let i = 5;
    while (i * i <= n) {
        if (n % i === 0 || n % (i + 2) === 0) {
            return false;
        }
        i += 6;
    }
    return true;
}
// helpers for getPrime end
function getPrimitiveRoot(modulus) {
    const phiM = eulerPhi(modulus);
    const factors = primeFactors(phiM);
    for (let x = 2; x < modulus; x++) {
        let check = true;
        const n = factors.length;
        for (let i = 0; i < n; i++) {
            if (powerMod(x, phiM / factors[i], modulus) === 1) {
                check = false;
                break;
            }
        }
        if (check) {
            return x;
        }
    }
    return NaN;
}
// helpers for getPrimitiveRoot
function eulerPhi(n) {
    const product = function (list) {
        return list.reduce((memo, number) => {
            return memo * number;
        }, 1);
    };
    const factors = primeFactors(n);
    // Product{p-1} for all prime factors p
    const N = product(factors.map(p => p - 1));
    // Product{p} for all prime factors p
    const D = product(factors);
    // Compose the product formula and return
    return n * N / D;
}
function primeFactors(n) {
    return factor(n).map(f => f.prime);
}
let primes;
function factor(num) {
    let n = num;
    if ((!primes) || (primes[primes.length - 1] < n)) {
        primes = sieve(n);
    }
    const factors = [];
    for (let k = 0; k < primes.length && n > 1; k++) {
        const p = primes[k];
        if (n % p === 0) {
            const factor = { prime: p, power: 0 };
            while (n % p === 0) {
                factor.power++;
                n /= p;
            }
            factors.push(factor);
        }
    }
    if (n > 1) {
        // Whatever remains, if it is not 1, must be prime
        factors.push({ prime: n, power: 1 });
    }
    return factors;
}
function sieve(n) {
    const numbers = new Buffer(n);
    for (let i = 0; i < n; i += 8) {
        numbers[i] = 1;
    }
    for (let i = 2; i < Math.sqrt(n); i++) {
        for (let j = i * i; j < n; j += i) {
            numbers[j] = 0;
        }
    }
    const primes = [];
    for (let i = 2; i < n; i++) {
        if (numbers[i]) {
            primes.push(i);
        }
    }
    return primes;
}
function powerMod(base, exponent, mod) {
    if (exponent < 0) {
        return inverseMod(powerMod(base, -exponent, mod), mod);
    }
    let result = 1;
    let myBase = base % mod;
    let myExponent = exponent;
    while (exponent > 0) {
        if (exponent % 2 === 1) {
            // Use modulus multiplication to avoid overflow
            result = multiplyMod(result, myBase, mod);
            myExponent -= 1;
        }
        // using /2 instead of >>1 to work with numbers up to 2^52
        myExponent /= 2;
        // Use modulus multiplication to avoid overflow
        myBase = multiplyMod(base, myBase, mod);
    }
    return result;
}
function multiplyMod(a, b, m) {
    // For small enough numbers, we can multiply without overflowing
    if ((a < 94906265) && (b < 94906265)) {
        return (a * b) % m;
    }
    let myA = a;
    let myB = b;
    let d = 0;
    // Bitshifts in javascript reduce everything to 32-bit ints, but with
    // division we can get 53-bit resolutions as myA float
    const mp2 = m / 2;
    if (myA >= m)
        myA %= m;
    if (myB >= m)
        myB %= m;
    for (let i = 0; i < primeBitLength; i++) {
        d = (d >= mp2) ? (2 * d - m) : (2 * d);
        // Checking top bit (but I can't use bitwise operators without coercing down
        // to 32 bits)
        if (myA >= 4503599627370496) {
            d += myB;
            myA = myA - 4503599627370495;
        }
        if (d > m) {
            d -= m;
        }
        myA *= 2;
    }
    return d;
}
function inverseMod(a, n) {
    const myA = a < 0 ? (a % n) + n : a;
    let t = 0;
    let newt = 1;
    let r = n;
    let newr = myA;
    while (newr !== 0) {
        const quotient = Math.floor(r / newr);
        const oldt = t;
        t = newt;
        newt = oldt - quotient * newt;
        const oldr = r;
        r = newr;
        newr = oldr - quotient * newr;
    }
    if (r > 1) {
        return NaN;
    }
    return (t > 0) ? t : (t + n);
}
// helpers for getPrimitiveRoot end
const crypto_2 = require("crypto");
const logger_service_1 = require("./logger.service");
const helper_service_1 = require("./helper.service");
const probableG = [2, 3, 5, 7, 11, 13, 17, 19];
function pg() {
    const g = probableG[Math.floor(Math.random() * probableG.length)];
    const dhPair = crypto_2.createDiffieHellman(primeBitLength, g);
    return {
        g: BigInt(g),
        p: BigInt(`0x${dhPair.getPrime('hex')}`),
    };
}
exports.pg = pg;
//# sourceMappingURL=diffie-hellman.service.js.map