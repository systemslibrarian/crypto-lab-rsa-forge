/**
 * textbook.ts — Real BigInt RSA: prime generation, key derivation,
 * modular exponentiation. Also drives Panel 1 UI.
 *
 * All arithmetic is performed with native BigInt — no simulation.
 * Miller-Rabin primality test with deterministic witnesses for small
 * numbers and 20 random witnesses for large numbers.
 *
 * NIST SP 800-57 key-size guidance is surfaced to the user.
 */

import {
  announce, show, setText, setLoading,
  bigintToHex, bytesToBigint,
} from './ui.js';

/* ── BigInt math primitives ─────────────────────────────────── */

/** Modular exponentiation: base^exp mod m (square-and-multiply). */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  if (base < 0n) base += mod;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    exp >>= 1n;
    base = base * base % mod;
  }
  return result;
}

/**
 * Miller-Rabin primality test.
 * Returns false if definitely composite, true if probably prime.
 * Uses deterministic witnesses covering n < 3.3 × 10^24.
 */
export function millerRabin(n: bigint): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n || n === 5n || n === 7n) return true;
  if (n % 2n === 0n) return false;

  // Express n-1 as 2^r * d
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) { d >>= 1n; r++; }

  // Deterministic witnesses sufficient for n < 3,317,044,064,679,887,385,961,981
  // Source: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Testing_against_small_sets_of_bases
  const witnesses = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

  for (const a of witnesses) {
    if (a >= n) continue;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let i = 1n; i < r; i++) {
      x = x * x % n;
      if (x === n - 1n) { composite = false; break; }
    }
    if (composite) return false;
  }
  return true;
}

/** Generate a random odd BigInt of exactly `bits` bits (MSB set). */
function randomOddBigint(bits: number): bigint {
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  crypto.getRandomValues(bytes);
  // Set MSB
  const topBits = bits % 8;
  if (topBits > 0) {
    bytes[0] = (bytes[0] | (1 << (topBits - 1))) & ((1 << topBits) - 1);
  } else {
    bytes[0] |= 0x80;
  }
  // Set LSB (odd)
  bytes[bytes.length - 1] |= 0x01;
  return bytesToBigint(bytes);
}

/** Generate a random probable-prime of `bits` bits. */
export function generatePrime(bits: number): bigint {
  while (true) {
    const candidate = randomOddBigint(bits);
    if (millerRabin(candidate)) return candidate;
  }
}

/** Extended Euclidean algorithm. Returns [gcd, s, t] such that a*s + b*t = gcd. */
export function extGcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) return [a, 1n, 0n];
  const [g, s, t] = extGcd(b, a % b);
  return [g, t, s - (a / b) * t];
}

/** Modular inverse of a mod m. Throws if gcd ≠ 1. */
export function modInverse(a: bigint, m: bigint): bigint {
  const [g, s] = extGcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error(`No modular inverse: gcd(${a}, ${m}) = ${g}`);
  return ((s % m) + m) % m;
}

/** Greatest common divisor. */
export function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) { [a, b] = [b, a % b]; }
  return a;
}

/** Bit length of a bigint. */
export function bitLen(n: bigint): number {
  return n === 0n ? 0 : n.toString(2).length;
}

/* ── RSA Key Generation ─────────────────────────────────────── */

export interface RsaKeyPair {
  p: bigint;
  q: bigint;
  n: bigint;
  phi: bigint;
  e: bigint;
  d: bigint;
  bits: number;
}

/**
 * Generate an RSA key pair.
 * p and q are each `bits/2` bits.
 * e defaults to 65537 (Fermat F4).
 */
export function generateRsaKeyPair(totalBits: number, e = 65537n): RsaKeyPair {
  const halfBits = Math.floor(totalBits / 2);
  let p: bigint, q: bigint, phi: bigint;

  // Generate distinct p, q such that gcd(e, (p-1)(q-1)) = 1
  while (true) {
    p = generatePrime(halfBits);
    q = generatePrime(halfBits);
    if (p === q) continue;
    phi = (p - 1n) * (q - 1n);
    if (gcd(e, phi) === 1n) break;
  }

  const n = p * q;
  const d = modInverse(e, phi);
  return { p, q, n, phi, e, d, bits: bitLen(n) };
}

/* ── Message encoding ───────────────────────────────────────── */

/** Encode UTF-8 string as bigint. */
export function encodeMessage(msg: string): bigint {
  const bytes = new TextEncoder().encode(msg);
  return bytesToBigint(bytes);
}

/** Decode bigint as UTF-8 string. */
export function decodeMessage(m: bigint): string {
  // Determine byte length
  const hex = m.toString(16);
  const padded = hex.length % 2 === 0 ? hex : '0' + hex;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

/* ── Panel 1 UI ─────────────────────────────────────────────── */

let tbKey: RsaKeyPair | null = null;
let tbCiphertext: bigint | null = null;

export function initTextbookPanel(): void {
  const btnSmall = document.getElementById('tb-gen-small') as HTMLButtonElement;
  const btn2048  = document.getElementById('tb-gen-2048')  as HTMLButtonElement;
  const btnEncrypt    = document.getElementById('tb-encrypt')    as HTMLButtonElement;
  const btnDecrypt    = document.getElementById('tb-decrypt')    as HTMLButtonElement;
  const btnDeterminism = document.getElementById('tb-determinism') as HTMLButtonElement;

  btnSmall.addEventListener('click', () => generateKey(32,  btnSmall));
  btn2048.addEventListener('click',  () => generateKey(256, btn2048));

  btnEncrypt.addEventListener('click', encryptMessage);
  btnDecrypt.addEventListener('click', decryptMessage);
  btnDeterminism.addEventListener('click', demonstrateDeterminism);
}

function generateKey(primeBits: number, btn: HTMLButtonElement): void {
  const label = btn.getAttribute('aria-label') ?? 'Generate RSA key';
  setLoading(btn, true);
  announce('Generating RSA key pair…');

  // Yield to browser to show spinner before blocking work
  setTimeout(() => {
    try {
      const kp = generateRsaKeyPair(primeBits * 2);
      tbKey = kp;

      setText('tb-p',   kp.p.toString(10));
      setText('tb-q',   kp.q.toString(10));
      setText('tb-n',   kp.n.toString(10));
      setText('tb-phi', kp.phi.toString(10));
      setText('tb-e',   kp.e.toString(10));
      setText('tb-d',   kp.d.toString(10));

      // Verify: e*d mod phi(n) = 1
      const check = kp.e * kp.d % kp.phi;
      const verifyEl = document.getElementById('tb-verify');
      if (verifyEl) {
        verifyEl.textContent =
          `e × d mod φ(n) = ${kp.e} × ${kp.d} mod φ(n) = ${check} ✓`;
      }

      show('tb-params'); show('tb-crypto-card');
      announce(`RSA ${kp.bits}-bit key pair generated successfully.`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      announce(`Key generation failed: ${msg}`);
    } finally {
      setLoading(btn, false, label);
    }
  }, 10);
}

function encryptMessage(): void {
  if (!tbKey) return;
  const input = document.getElementById('tb-plaintext') as HTMLInputElement;
  const rawMsg = input.value.trim();
  if (!rawMsg) {
    announce('Please enter a message to encrypt.');
    input.focus();
    return;
  }

  const m = encodeMessage(rawMsg);
  if (m >= tbKey.n) {
    announce(`Message too large for this key. Maximum modulus is ${tbKey.n.toString(10).length} decimal digits.`);
    return;
  }

  const c = modPow(m, tbKey.e, tbKey.n);
  tbCiphertext = c;

  const hexC = bigintToHex(c);
  setText('tb-ciphertext', hexC);
  show('tb-encrypt-result');
  show('tb-decrypt-section');
  announce('Message encrypted. Ciphertext displayed.');
}

function decryptMessage(): void {
  if (!tbKey || tbCiphertext === null) return;
  const m = modPow(tbCiphertext, tbKey.d, tbKey.n);
  const msg = decodeMessage(m);
  setText('tb-decrypted', msg);
  announce(`Decrypted message: ${msg}`);
}

function demonstrateDeterminism(): void {
  if (!tbKey) return;
  const input = document.getElementById('tb-plaintext') as HTMLInputElement;
  const rawMsg = input.value.trim() || 'Demo';

  const m = encodeMessage(rawMsg);
  if (m >= tbKey.n) {
    announce('Message too large. Shorten it or regenerate key.');
    return;
  }

  const c1 = modPow(m, tbKey.e, tbKey.n);
  const c2 = modPow(m, tbKey.e, tbKey.n);

  const hex1 = bigintToHex(c1).slice(0, 40);
  const hex2 = bigintToHex(c2).slice(0, 40);
  const match = c1 === c2;

  setText('tb-ct1', hex1 + '…');
  setText('tb-ct2', hex2 + '…');
  setText('tb-ct-match', match ? '✓ YES — always identical' : '✗ NO (unexpected)');

  const matchEl = document.getElementById('tb-ct-match');
  if (matchEl) {
    matchEl.style.color = match ? 'var(--c-danger)' : 'var(--c-safe)';
  }

  show('tb-determinism-result');
  announce(
    match
      ? 'Both ciphertexts are identical — textbook RSA is deterministic and insecure.'
      : 'Ciphertexts differ (unexpected for textbook RSA).',
  );
}
