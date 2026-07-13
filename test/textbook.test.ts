import { describe, it, expect } from 'vitest';
import {
  modPow, millerRabin, extGcd, modInverse, gcd, bitLen,
  generateRsaKeyPair, generatePrime, encodeMessage, decodeMessage,
  isqrt, trialFactor,
} from '../src/textbook.js';

describe('modPow — modular exponentiation', () => {
  it('matches known small values', () => {
    expect(modPow(2n, 10n, 1000n)).toBe(24n);      // 1024 mod 1000
    expect(modPow(3n, 0n, 7n)).toBe(1n);           // anything^0 = 1
    expect(modPow(5n, 3n, 13n)).toBe(8n);          // 125 mod 13
    expect(modPow(7n, 256n, 13n)).toBe(9n);        // large exponent
  });

  it('handles mod 1 and negative base', () => {
    expect(modPow(7n, 5n, 1n)).toBe(0n);
    expect(modPow(-3n, 3n, 7n)).toBe(modPow(4n, 3n, 7n)); // -3 ≡ 4 (mod 7)
  });

  it('agrees with Fermat: a^(p-1) ≡ 1 (mod p) for prime p', () => {
    const p = 1000003n; // prime
    for (const a of [2n, 3n, 5n, 123456n]) {
      expect(modPow(a, p - 1n, p)).toBe(1n);
    }
  });

  it('is a true RSA encrypt/decrypt inverse over a real key', () => {
    const kp = generateRsaKeyPair(256, 65537n);
    const m = 424242424242n;
    const c = modPow(m, kp.e, kp.n);
    expect(modPow(c, kp.d, kp.n)).toBe(m);
  });
});

describe('millerRabin — primality', () => {
  it('recognises small primes and composites', () => {
    const primes = [2n, 3n, 5n, 7n, 11n, 13n, 97n, 7919n];
    const composites = [0n, 1n, 4n, 9n, 15n, 21n, 100n, 7917n];
    for (const p of primes) expect(millerRabin(p)).toBe(true);
    for (const c of composites) expect(millerRabin(c)).toBe(false);
  });

  it('rejects strong pseudoprimes to base 2 (2047, 3277)', () => {
    // 2047 = 23·89 is a base-2 Fermat/strong pseudoprime; a naive base-2-only
    // test would call it prime. Our multi-witness set must catch it.
    expect(millerRabin(2047n)).toBe(false);
    expect(millerRabin(3277n)).toBe(false);
    // 25326001 is a strong pseudoprime to bases 2,3,5 simultaneously.
    expect(millerRabin(25326001n)).toBe(false);
  });

  it('accepts large known primes', () => {
    // Mersenne prime 2^61 - 1 and a couple of hand-picked primes.
    expect(millerRabin((1n << 61n) - 1n)).toBe(true);
    expect(millerRabin(2305843009213693951n)).toBe(true);
    expect(millerRabin(999999999989n)).toBe(true);
  });

  it('rejects a Carmichael number (561 = 3·11·17)', () => {
    expect(millerRabin(561n)).toBe(false);
    expect(millerRabin(41041n)).toBe(false); // Carmichael
  });
});

describe('extGcd / modInverse / gcd', () => {
  it('extGcd returns a Bézout identity', () => {
    const [g, s, t] = extGcd(240n, 46n);
    expect(g).toBe(2n);
    expect(240n * s + 46n * t).toBe(g);
  });

  it('modInverse is a genuine inverse', () => {
    expect((3n * modInverse(3n, 11n)) % 11n).toBe(1n);
    expect((17n * modInverse(17n, 3120n)) % 3120n).toBe(1n); // classic RSA d
    const inv = modInverse(65537n, 999983n * 999979n - 999983n - 999979n + 1n);
    expect(inv > 0n).toBe(true);
  });

  it('modInverse throws when no inverse exists', () => {
    expect(() => modInverse(6n, 9n)).toThrow(); // gcd(6,9)=3
  });

  it('gcd is correct and non-negative', () => {
    expect(gcd(54n, 24n)).toBe(6n);
    expect(gcd(-54n, 24n)).toBe(6n);
    expect(gcd(17n, 0n)).toBe(17n);
  });
});

describe('bitLen', () => {
  it('counts bits correctly', () => {
    expect(bitLen(0n)).toBe(0);
    expect(bitLen(1n)).toBe(1);
    expect(bitLen(255n)).toBe(8);
    expect(bitLen(256n)).toBe(9);
  });
});

describe('generatePrime / generateRsaKeyPair', () => {
  it('generatePrime returns a prime of the requested bit length', () => {
    const p = generatePrime(64);
    expect(bitLen(p)).toBe(64);
    expect(millerRabin(p)).toBe(true);
  });

  it('produces a self-consistent RSA key (e·d ≡ 1 mod φ, n = p·q)', () => {
    const kp = generateRsaKeyPair(128, 65537n);
    expect(kp.p * kp.q).toBe(kp.n);
    expect((kp.p - 1n) * (kp.q - 1n)).toBe(kp.phi);
    expect((kp.e * kp.d) % kp.phi).toBe(1n);
    expect(kp.p).not.toBe(kp.q);
    expect(gcd(kp.e, kp.phi)).toBe(1n);
  });
});

describe('isqrt — integer square root', () => {
  it('is exact on perfect squares and floors otherwise', () => {
    expect(isqrt(0n)).toBe(0n);
    expect(isqrt(1n)).toBe(1n);
    expect(isqrt(15n)).toBe(3n);
    expect(isqrt(16n)).toBe(4n);
    expect(isqrt(9999n)).toBe(99n);
    expect(isqrt(1n << 100n)).toBe(1n << 50n);
  });
});

describe('trialFactor — honest small-modulus factoring (factoring wall)', () => {
  it('recovers the two primes of a real small RSA modulus', () => {
    const kp = generateRsaKeyPair(32, 65537n); // two 16-bit primes → 32-bit n
    const res = trialFactor(kp.n);
    expect(res).not.toBeNull();
    const { p, q } = res!;
    expect(p * q).toBe(kp.n);
    // Order-agnostic: {p,q} equals the key's {p,q}.
    const got = [p, q].sort((a, b) => (a < b ? -1 : 1));
    const want = [kp.p, kp.q].sort((a, b) => (a < b ? -1 : 1));
    expect(got).toEqual(want);
  });

  it('factors an even modulus immediately via 2', () => {
    expect(trialFactor(2n * 7919n)).toEqual({ p: 2n, q: 7919n, trials: 1 });
  });

  it('respects the work budget and returns null instead of hanging', () => {
    // A large semiprime with tiny budget must give up rather than spin.
    const big = 1000003n * 1000033n; // both prime, ~40-bit n
    expect(trialFactor(big, 5)).toBeNull();
  });
});

describe('encodeMessage / decodeMessage round-trip', () => {
  it('recovers ASCII and UTF-8 strings', () => {
    for (const s of ['Hi!', 'RSA Forge', 'héllo', '🔐key']) {
      expect(decodeMessage(encodeMessage(s))).toBe(s);
    }
  });
});
