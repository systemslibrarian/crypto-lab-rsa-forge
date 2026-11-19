/**
 * Fault the verifier, not the signer.
 *
 * Every other fault panel in this lab faults the SIGNER's CRT computation.
 * Seifert's attack faults the VERIFIER instead. The modulus N sits in the
 * device's memory; the attacker flips or zeroes a few bits of it until the
 * faulted modulus N̂ is prime, or splits into small primes. For such an N̂ the
 * attacker can compute a matching private exponent d̂ = e⁻¹ mod φ(N̂) — no
 * factoring of the real N, no secret key — and sign anything. The device,
 * verifying under N̂, accepts. An honest device, verifying under N, rejects.
 *
 *   J. A. Muir, "Seifert's RSA Fault Attack: Simplified Analysis and
 *   Generalizations" (2005), §2–§4; the worked modulus is §4.3.
 *   Original: J.-P. Seifert, "On authenticated computing and RSA-based
 *   authentication" (ACM CCS 2005).
 *
 * All arithmetic here is real BigInt. Nothing is faulted in WebCrypto; the
 * "device" is a function in this file that verifies against whichever modulus
 * it is handed.
 */
import { modPow, millerRabin, modInverse, gcd, bitLen, generateRsaKeyPair } from './textbook.js';

const mod = (x: bigint, n: bigint): bigint => ((x % n) + n) % n;

/** SHA-256 of a UTF-8 message as an integer. A stand-in for the device's H(m). */
export async function hashToInt(message: string): Promise<bigint> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(message)));
  let h = 0n;
  for (const b of digest) h = (h << 8n) | BigInt(b);
  return h;
}

/** The RSA verifier a device runs: accept iff s^e ≡ h (mod modulus). */
export function verify(signature: bigint, h: bigint, e: bigint, modulus: bigint): boolean {
  return modPow(signature, e, modulus) === mod(h, modulus);
}

/**
 * Zero or flip one byte of N. Byte 0 is the least significant, as Muir §4.3
 * indexes them. `mode` is the two fault shapes the paper models: `zero` clears
 * the byte (the Xbox search), `flip` XORs it with a random non-zero mask.
 */
export function faultByte(n: bigint, byteIndex: number, mode: 'zero' | 'flip', mask?: number): bigint {
  const shift = 8n * BigInt(byteIndex);
  const current = Number((n >> shift) & 0xffn);
  if (mode === 'zero') return n - (BigInt(current) << shift);
  const m = mask ?? ((current ^ ((Math.floor(Math.random() * 255) + 1))) & 0xff) ^ current;
  const applied = (m & 0xff) || 1; // never a no-op
  return n ^ (BigInt(applied) << shift);
}

export interface Forgeability {
  forgeable: boolean;
  /** Why not, when it is not: 'unchanged', 'even', 'e-not-coprime', 'not-factorable'. */
  reason?: 'unchanged' | 'even' | 'e-not-coprime' | 'not-factorable';
  /** Distinct prime factors found (N̂ must be squarefree for φ to be a product of (pᵢ−1)). */
  factors?: bigint[];
  /** φ(N̂), when forgeable. */
  phi?: bigint;
  /** d̂ = e⁻¹ mod φ(N̂), when forgeable. */
  dHat?: bigint;
  /** 'prime' when N̂ itself is prime; 'factored' when it split into small primes × a prime cofactor. */
  route?: 'prime' | 'factored';
}

/**
 * Can the attacker forge under N̂? Yes when N̂ is squarefree with a known
 * factorization and gcd(e, φ(N̂)) = 1.
 *
 * Two routes, matching the paper: Seifert's original asks for N̂ PRIME (§3),
 * so φ = N̂ − 1; Muir's §4 improvement divides out small primes up to
 * `smallLimit` and accepts if the cofactor is 1 or prime, so φ = Π(pᵢ − 1).
 */
export function analyzeFaulted(nHat: bigint, N: bigint, e: bigint, smallLimit = 1n << 20n): Forgeability {
  if (nHat === N) return { forgeable: false, reason: 'unchanged' };
  if (nHat <= 2n || nHat % 2n === 0n) return { forgeable: false, reason: 'even' };

  if (millerRabin(nHat)) {
    const phi = nHat - 1n;
    if (gcd(e, phi) !== 1n) return { forgeable: false, reason: 'e-not-coprime', factors: [nHat] };
    return { forgeable: true, factors: [nHat], phi, dHat: modInverse(e, phi), route: 'prime' };
  }

  // Divide out distinct small primes; a repeated factor makes φ ≠ Π(pᵢ−1), so refuse.
  const factors: bigint[] = [];
  let cof = nHat;
  for (let p = 3n; p <= smallLimit; p += 2n) {
    if (cof % p === 0n) {
      factors.push(p);
      cof /= p;
      if (cof % p === 0n) return { forgeable: false, reason: 'not-factorable' }; // not squarefree
    }
    if (cof === 1n || p * p > cof) break;
  }
  if (cof !== 1n) {
    if (!millerRabin(cof)) return { forgeable: false, reason: 'not-factorable' };
    if (factors.some((p) => p === cof)) return { forgeable: false, reason: 'not-factorable' };
    factors.push(cof);
  }
  if (factors.length < 2) return { forgeable: false, reason: 'not-factorable' };
  let phi = 1n;
  for (const p of factors) phi *= p - 1n;
  if (gcd(e, phi) !== 1n) return { forgeable: false, reason: 'e-not-coprime', factors };
  return { forgeable: true, factors, phi, dHat: modInverse(e, phi), route: 'factored' };
}

export interface ToyFaultSearch {
  byteIndex: number;
  /** The original value of that byte in N. */
  originalByte: number;
  /** The value the fault put there. */
  faultedByte: number;
  nHat: bigint;
  analysis: Forgeability;
  /** How many candidate byte values were examined before this one. */
  tried: number;
}

/**
 * Fault one byte of N until a forgeable N̂ appears.
 *
 * This is Muir's §2 "random-data, fixed-location" fault: the byte at a fixed
 * offset takes an arbitrary value the attacker cannot choose but can retry. We
 * walk the low byte through every value, then the next byte, and return the
 * first forgeable N̂ — overwhelmingly a prime one, since over 256 values of a
 * single byte the prime density makes one all but certain. Deterministic
 * given N.
 */
export function searchToyFault(N: bigint, e: bigint, maxByte = 8): ToyFaultSearch | null {
  let tried = 0;
  for (let byteIndex = 0; byteIndex <= maxByte; byteIndex++) {
    const shift = 8n * BigInt(byteIndex);
    const original = Number((N >> shift) & 0xffn);
    const base = N - (BigInt(original) << shift);
    for (let value = 0; value < 256; value++) {
      if (value === original) continue; // no fault
      tried++;
      const nHat = base + (BigInt(value) << shift);
      const analysis = analyzeFaulted(nHat, N, e);
      if (analysis.forgeable) {
        return { byteIndex, originalByte: original, faultedByte: value, nHat, analysis, tried };
      }
    }
  }
  return null;
}

export interface ToyRun {
  bits: number;
  N: bigint;
  e: bigint;
  message: string;
  h: bigint;
  search: ToyFaultSearch;
  /** s = h^d̂ mod N̂ — a forged signature under the faulted modulus. */
  forgedSignature: bigint;
  /** The faulted device (verifies under N̂) accepts it. */
  faultedAccepts: boolean;
  /** An honest device (verifies under the real N) rejects it. */
  honestAccepts: boolean;
}

/**
 * A full toy attack: real RSA key, a faulted modulus found by search, a forged
 * signature on an arbitrary message, and the two verdicts. `keygen` is
 * injectable so a test can pin the key.
 */
export async function runToyAttack(
  message: string,
  bits = 512,
  e = 65537n,
  keygen: (b: number, e: bigint) => { n: bigint } = (b, exp) => generateRsaKeyPair(b, exp),
): Promise<ToyRun | { error: 'no-fault-found' }> {
  const key = keygen(bits, e);
  const N = key.n;
  const search = searchToyFault(N, e);
  if (!search) return { error: 'no-fault-found' };
  const h = mod(await hashToInt(message), search.nHat);
  const forgedSignature = modPow(h, search.analysis.dHat!, search.nHat);
  return {
    bits,
    N,
    e,
    message,
    h,
    search,
    forgedSignature,
    faultedAccepts: verify(forgedSignature, h, e, search.nHat),
    honestAccepts: verify(forgedSignature, mod(await hashToInt(message), N), e, N),
  };
}

// ---------------------------------------------------------------------------
// The real 2048-bit Xbox modulus (Muir §4.3), and the two facts the paper states.
// ---------------------------------------------------------------------------

/**
 * The 2048-bit RSA modulus Microsoft stored in the Xbox, exactly as printed in
 * Muir §4.3 (hexadecimal, most-significant byte first, from the "Operation X"
 * source). Nothing is derived from it that is not computed below.
 */
export const XBOX_MODULUS_HEX =
  'A44B1BBD7EDA72C7143CD5C2D4BA880C7681832D5198F75FCAB1618598E2B3E4' +
  '8D9A47B0BFF6BC967CAE88F198266E535A6CB41B470C0A38A19D8F57CB11F568' +
  'DB52CF69E49F604EEA52F4EB9D37E80C60BD70A5CF5A67EC05AA6B3E8C80C116' +
  '819A14892BFA7603BECE39F09C42724EE9F371C473AAA09FEDA34F9EA1019827' +
  'BD07CA52A80013BE9471E46FCF1CA4D915FB9DF95E9344330B6AAE0B90526AD1' +
  'BE475D10797526075C9206FF758A3EB3BAF7C0A22E51645BB9F13FE129A22F2E' +
  '1BEDDA95D68AFC6D46585B01FBB5737273C6AEE399148C5B8E77B479DE8B05BD' +
  'EEC27FEFFF7B349C64F51002D2F6522ED43617F2A1A3D4C2E6D73D66E54ED7D3';

export const XBOX_MODULUS = BigInt('0x' + XBOX_MODULUS_HEX);

/** Muir §4.3: "The modulus above consists of 256 bytes." */
export const XBOX_BYTES = 256;

export interface XboxPrimeSearch {
  /** The smallest byte index whose zeroing makes the modulus prime. Muir says 104. */
  smallestPrimeByte: number;
  /** Byte indices examined. */
  scanned: number;
}

/**
 * The smallest index j such that zeroing byte j of the Xbox modulus gives a
 * prime. Muir §4.3 states j = 104. Computed here with the same Miller-Rabin
 * the rest of the lab uses; nothing is asserted that the search does not find.
 */
export function xboxSmallestPrimeByte(): XboxPrimeSearch {
  for (let j = 0; j < XBOX_BYTES; j++) {
    const current = Number((XBOX_MODULUS >> (8n * BigInt(j))) & 0xffn);
    if (current === 0) continue;
    const candidate = faultByte(XBOX_MODULUS, j, 'zero');
    if (millerRabin(candidate)) return { smallestPrimeByte: j, scanned: j + 1 };
  }
  return { smallestPrimeByte: -1, scanned: XBOX_BYTES };
}

export interface XboxByte16 {
  /** N̂ with byte 16 zeroed. */
  nHat: bigint;
  /** The small prime factors Muir names: 3, 13, 199, 856469. */
  smallFactors: bigint[];
  /** The large prime cofactor p₀. */
  cofactor: bigint;
  /** p₀ passes Miller-Rabin. */
  cofactorIsPrime: boolean;
  /** Bit length of p₀. */
  cofactorBits: number;
  /** The named small factors multiply the cofactor back to N̂. */
  productMatches: boolean;
}

/**
 * Muir §4.3: zeroing byte 16 of the Xbox modulus gives 3 · 13 · 199 · 856469 · p₀
 * with p₀ a large prime. Reproduced by dividing out exactly those four primes
 * and testing the cofactor.
 */
export function xboxByte16Factorization(): XboxByte16 {
  const nHat = faultByte(XBOX_MODULUS, 16, 'zero');
  const smallFactors = [3n, 13n, 199n, 856469n];
  let cofactor = nHat;
  let product = 1n;
  const divided: bigint[] = [];
  for (const p of smallFactors) {
    if (cofactor % p === 0n) {
      cofactor /= p;
      product *= p;
      divided.push(p);
    }
  }
  return {
    nHat,
    smallFactors: divided,
    cofactor,
    cofactorIsPrime: millerRabin(cofactor),
    cofactorBits: bitLen(cofactor),
    productMatches: product * cofactor === nHat && divided.length === smallFactors.length,
  };
}

/**
 * Muir §3.2 success probabilities for Seifert's original (prime-N̂) search:
 * 1 − (1 − p)^(2^b − 1) with p ≈ 0.00282 (RSA-1024, e = 65537). The general
 * formula is set up in §3.1 ("Analysis"); the RSA-1024 base probability 0.00282
 * and these b = 4/6/8/10 values live in §3.2 ("The off-line search in practice").
 *
 * These are the §3.2 figures, NOT Figure 3's "Seifert" column — the b = 6 cell
 * of Figure 3 reads 0.084 and is wrong (it uses 2^5 − 1 trials where the text
 * uses 2^6 − 1). The b = 4 and b = 8 rows agree between the two. This function
 * computes the §3.2 formula, so b = 6 gives ≈ 0.163, matching the paper's text.
 */
export function seifertSuccessProbability(b: number, perTrial = 0.00282): number {
  return 1 - Math.pow(1 - perTrial, 2 ** b - 1);
}
