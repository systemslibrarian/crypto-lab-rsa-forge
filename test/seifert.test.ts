/**
 * Fault the verifier (Seifert's attack), as executable claims.
 *
 * Muir, "Seifert's RSA Fault Attack: Simplified Analysis and Generalizations"
 * (2005), §2–§4. The two Xbox facts (§4.3) are reproduced from the real
 * 2048-bit modulus; the toy forgery is run end to end on a real small key.
 */
import { describe, it, expect } from 'vitest';
import {
  XBOX_MODULUS,
  XBOX_MODULUS_HEX,
  analyzeFaulted,
  faultByte,
  hashToInt,
  runToyAttack,
  seifertSuccessProbability,
  verify,
  xboxByte16Factorization,
  xboxSmallestPrimeByte,
} from '../src/seifert.ts';
import { generateRsaKeyPair, millerRabin, modPow } from '../src/textbook.ts';

describe('the Xbox modulus (Muir §4.3)', () => {
  it('is the 2048-bit value printed in the paper', () => {
    expect(XBOX_MODULUS_HEX).toHaveLength(512); // 256 bytes
    expect(XBOX_MODULUS.toString(2).length).toBe(2048);
    expect(XBOX_MODULUS_HEX[0]).toBe('A'); // top nibble, so exactly 2048 bits
    expect(XBOX_MODULUS % 2n).toBe(1n);
  });

  it('byte 104 is the smallest zeroing that makes it prime', () => {
    const { smallestPrimeByte, examined } = xboxSmallestPrimeByte();
    expect(smallestPrimeByte).toBe(104);
    // The one search is its own evidence: byte 104 was tested and found prime,
    // and every non-zero byte below it was tested and found composite. Read
    // those recorded verdicts rather than re-running the (costly) 2048-bit scan.
    expect(examined.find((e) => e.byte === 104)?.isPrime).toBe(true);
    for (const e of examined) {
      if (e.byte < 104) expect(e.isPrime, `byte ${e.byte}`).toBe(false);
    }
  });

  it('zeroing byte 16 gives 3 · 13 · 199 · 856469 · p₀ with p₀ a large prime', () => {
    const f = xboxByte16Factorization();
    expect(f.smallFactors).toEqual([3n, 13n, 199n, 856469n]);
    expect(f.cofactorIsPrime).toBe(true);
    expect(f.productMatches).toBe(true);
    expect(3n * 13n * 199n * 856469n * f.cofactor).toBe(f.nHat);
    expect(f.cofactorBits).toBeGreaterThan(2000); // a 2015-bit prime
    // byte 16's zeroed value is forgeable by the factored route.
    const a = analyzeFaulted(f.nHat, XBOX_MODULUS, 65537n);
    expect(a.forgeable).toBe(true);
    expect(a.route).toBe('factored');
  });
});

describe('forgeability analysis', () => {
  it('a prime N̂ is forgeable, φ = N̂ − 1, and d̂ inverts e', () => {
    // A FIXED 256-bit modulus whose byte-0 search finds a prime (at v = 47).
    // A fresh random key was used here before, with a byte-0-only search and a
    // comment that the "prime density makes this reliable" -- it does not: over
    // ~128 odd candidates near a 256-bit value the chance of finding no prime is
    // ~30-50%, so the search returned null and the test failed about a third of
    // runs. Fixing the modulus makes the search deterministic; the demo still
    // generates keys at runtime.
    const N = 0x9b43a24488fcdbb38722825c1d6dc289d8c38f8a20f715319f907fa284b33aabn;
    // Find the prime fault by trying byte-0 values; for this N it is at v = 47.
    let primeHat: bigint | null = null;
    const base = N - (N & 0xffn);
    for (let v = 0; v < 256 && !primeHat; v++) {
      const cand = base + BigInt(v);
      if (cand !== N && cand % 2n === 1n && millerRabin(cand)) primeHat = cand;
    }
    expect(primeHat).not.toBeNull();
    const a = analyzeFaulted(primeHat!, N, 65537n);
    expect(a.forgeable).toBe(true);
    expect(a.route).toBe('prime');
    expect(a.phi).toBe(primeHat! - 1n);
    expect((65537n * a.dHat!) % a.phi!).toBe(1n);
  });

  it('refuses an unchanged modulus, an even one, and a true RSA N', () => {
    const key = generateRsaKeyPair(256, 65537n);
    expect(analyzeFaulted(key.n, key.n, 65537n).reason).toBe('unchanged');
    expect(analyzeFaulted(100n, 99n, 65537n).reason).toBe('even');
    // A genuine RSA modulus has two large prime factors and is not forgeable
    // by small-prime division.
    const other = generateRsaKeyPair(256, 65537n).n;
    expect(analyzeFaulted(other, key.n, 65537n).forgeable).toBe(false);
  });
});

// A precomputed FORGEABLE 512-bit modulus (zeroing/searching byte 0 gives a
// prime N̂). The end-to-end attack is run against this fixed key, deterministically
// and in bounded time, instead of generating a fresh random key per call:
// generateRsaKeyPair occasionally spent >2s on an unlucky prime search, and three
// such keygens in one test timed out at the 5s default. The attack does not depend
// on the message, only on the key; the live demo still generates keys at runtime.
const FORGEABLE_N_512 =
  0x67f58c104a0e37e7b2c01d1c8ae6c321085303b4e0491243bc3e078b05a88c875c77b70bf036fe19f98bd70249b3e001bace9764bccea834d9afebfdce20a4f3n;
const fixedKeygen = (): { n: bigint } => ({ n: FORGEABLE_N_512 });

describe('the toy attack, end to end', () => {
  it('forges a signature the faulted device accepts and the honest device rejects', async () => {
    for (const message of ['run my unsigned code', 'any message at all', 'ship it']) {
      const run = await runToyAttack(message, 512, 65537n, fixedKeygen);
      expect('error' in run).toBe(false);
      if ('error' in run) continue;
      expect(run.search.analysis.forgeable).toBe(true);
      // The forged signature verifies under N̂ ...
      expect(run.faultedAccepts).toBe(true);
      // ... and does not under the real N.
      expect(run.honestAccepts).toBe(false);
      // N̂ differs from N by exactly the one faulted byte.
      expect(run.search.nHat).not.toBe(run.N);
      const shift = 8n * BigInt(run.search.byteIndex);
      expect(run.N & ~(0xffn << shift)).toBe(run.search.nHat & ~(0xffn << shift));
      expect((run.search.nHat >> shift) & 0xffn).toBe(BigInt(run.search.faultedByte));
      expect((run.N >> shift) & 0xffn).toBe(BigInt(run.search.originalByte));
      // Re-derive the verification independently of the module's own verify().
      expect(modPow(run.forgedSignature, run.e, run.search.nHat)).toBe(run.h);
    }
  });

  it('the attacker never uses the real factors: a wrong modulus does not verify', async () => {
    const run = await runToyAttack('no secret key needed', 512, 65537n, fixedKeygen);
    expect('error' in run).toBe(false);
    if ('error' in run) return;
    // s was built from d̂ = e⁻¹ mod φ(N̂). Verifying it under a DIFFERENT prime
    // modulus must fail — the forgery is specific to the faulted N̂.
    const otherPrime = faultByte(run.search.nHat, 1, 'flip', 0x02);
    expect(verify(run.forgedSignature, run.h, run.e, otherPrime)).toBe(false);
  });
});

describe('Muir §3.2 success probabilities (not Figure 3’s b=6)', () => {
  it('reproduces the §3.2 formula values for RSA-1024', () => {
    // 1 − (1 − 0.00282)^(2^b − 1).
    expect(seifertSuccessProbability(4)).toBeCloseTo(0.0415, 3);
    expect(seifertSuccessProbability(6)).toBeCloseTo(0.163, 3);
    expect(seifertSuccessProbability(8)).toBeCloseTo(0.513, 3);
    // b = 6 is 0.163, NOT Figure 3's 0.084. The bug there uses 2^5 − 1 trials.
    const wrongFigure3 = 1 - Math.pow(1 - 0.00282, 2 ** 5 - 1);
    expect(wrongFigure3).toBeCloseTo(0.084, 3);
    expect(seifertSuccessProbability(6)).not.toBeCloseTo(0.084, 2);
  });
});

describe('hashToInt', () => {
  it('is a 256-bit function of the message', async () => {
    const a = await hashToInt('a');
    const b = await hashToInt('b');
    expect(a).not.toBe(b);
    expect(a.toString(2).length).toBeLessThanOrEqual(256);
  });
});
