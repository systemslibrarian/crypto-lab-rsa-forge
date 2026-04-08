/**
 * attacks.ts — Real attack demonstrations.
 *
 * Panel 4: Håstad Broadcast Attack (small exponent, e=3)
 *   – Real CRT reconstruction of m³ using BigInt arithmetic.
 *   – Real integer cube root via Newton's method.
 *   Ref: Håstad (1988); Coppersmith (1997).
 *
 * Panel 5: Bleichenbacher PKCS#1 v1.5 Padding Oracle
 *   – Real PKCS#1 v1.5 padding and unpadding on small RSA (128-bit).
 *   – Real oracle (checks actual decryption output).
 *   – Real Bleichenbacher adaptive chosen-ciphertext attack.
 *   Ref: Bleichenbacher (1998), "Chosen Ciphertext Attacks Against
 *        Protocols Based on the RSA Encryption Standard PKCS #1."
 */

import {
  modPow, generateRsaKeyPair, modInverse,
  encodeMessage, decodeMessage,
  type RsaKeyPair,
} from './textbook.js';
import {
  announce, announceUrgent, show, hide, setText, setLoading,
  bigintToHex, bigintToBytes, bytesToBigint, fromHex, ceilDiv,
} from './ui.js';

/* ════════════════════════════════════════════════════════════
   BigInt arithmetic helpers
   ════════════════════════════════════════════════════════════ */

/** Integer cube root via Newton's method (exact for perfect cubes). */
function intCubeRoot(n: bigint): bigint {
  if (n === 0n) return 0n;
  if (n < 0n) throw new Error('Negative cube root not supported');

  // Initial estimate: 2^(ceil(bit_length/3))
  const bits = n.toString(2).length;
  let x = 1n << BigInt(Math.ceil(bits / 3) + 1);

  while (true) {
    const x2 = x * x;
    const x1 = (2n * x + n / x2) / 3n;
    if (x1 >= x) break;
    x = x1;
  }
  // Newton converges from above; step down to find exact floor
  while (x * x * x > n) x--;
  return x;
}

/** Chinese Remainder Theorem for 3 congruences.
 *  Returns x such that x ≡ a_i (mod n_i), with 0 ≤ x < N = n1·n2·n3.
 *  Ref: Shoup, "A Computational Introduction to Number Theory and Algebra."
 */
function crt3(
  a1: bigint, n1: bigint,
  a2: bigint, n2: bigint,
  a3: bigint, n3: bigint,
): bigint {
  const N = n1 * n2 * n3;
  const N1 = n2 * n3;
  const N2 = n1 * n3;
  const N3 = n1 * n2;
  const e1 = modInverse(N1, n1);
  const e2 = modInverse(N2, n2);
  const e3 = modInverse(N3, n3);
  const x = (a1 * N1 * e1 + a2 * N2 * e2 + a3 * N3 * e3) % N;
  return (x + N) % N;
}

/* ════════════════════════════════════════════════════════════
   Panel 4 — Håstad Broadcast Attack
   ════════════════════════════════════════════════════════════ */

interface HastadState {
  keys: RsaKeyPair[];
  broadcast: { c1: bigint; c2: bigint; c3: bigint } | null;
}

const hastad: HastadState = { keys: [], broadcast: null };

export function initHastadPanel(): void {
  (document.getElementById('hastad-setup') as HTMLButtonElement)
    .addEventListener('click', hastadSetup);
  (document.getElementById('hastad-broadcast') as HTMLButtonElement)
    .addEventListener('click', hastadBroadcast);
  (document.getElementById('hastad-attack') as HTMLButtonElement)
    .addEventListener('click', hastadAttack);
}

function hastadSetup(): void {
  const btn = document.getElementById('hastad-setup') as HTMLButtonElement;
  const lbl = btn.getAttribute('aria-label') ?? '';
  setLoading(btn, true);
  announce('Generating 3 RSA key pairs with e=3…');

  setTimeout(() => {
    try {
      // 64-bit RSA keys (two 32-bit primes each) — small for demo visibility
      // Message must fit: m < n_i, so m < ~2^64.
      // Use e=3, ensure gcd(3, phi(n)) = 1.
      const keys: RsaKeyPair[] = [];
      for (let i = 0; i < 3; i++) {
        keys.push(generateRsaKeyPair(64, 3n));
      }
      hastad.keys = keys;
      hastad.broadcast = null;

      for (let i = 0; i < 3; i++) {
        setText(`hastad-n${i + 1}`, '0x' + bigintToHex(keys[i].n));
      }

      show('hastad-recipients');
      show('hastad-broadcast-card');
      announce('Three RSA key pairs (e=3) generated successfully.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      announce(`Setup failed: ${msg}`);
    } finally {
      setLoading(btn, false, lbl);
    }
  }, 10);
}

function hastadBroadcast(): void {
  if (hastad.keys.length < 3) { announce('Generate recipient keys first.'); return; }

  const input = document.getElementById('hastad-message') as HTMLInputElement;
  const rawMsg = input.value.trim() || 'Hello!';
  const m = encodeMessage(rawMsg);

  // Verify m < all moduli
  for (let i = 0; i < 3; i++) {
    if (m >= hastad.keys[i].n) {
      announce(`Message is too large for recipient ${i + 1}. Shorten the message.`);
      return;
    }
  }

  const [k1, k2, k3] = hastad.keys;
  const c1 = modPow(m, 3n, k1.n);
  const c2 = modPow(m, 3n, k2.n);
  const c3 = modPow(m, 3n, k3.n);

  hastad.broadcast = { c1, c2, c3 };

  setText('hastad-c1', '0x' + bigintToHex(c1));
  setText('hastad-c2', '0x' + bigintToHex(c2));
  setText('hastad-c3', '0x' + bigintToHex(c3));
  show('hastad-ciphertexts');
  show('hastad-attack-card');
  announce('Message broadcast to 3 recipients. Ciphertexts are visible to the attacker.');
}

function hastadAttack(): void {
  if (!hastad.broadcast || hastad.keys.length < 3) {
    announce('Broadcast the message first.');
    return;
  }

  const { c1, c2, c3 } = hastad.broadcast;
  const [k1, k2, k3] = hastad.keys;

  // Step 1: CRT reconstruction of m^3
  const M3 = crt3(c1, k1.n, c2, k2.n, c3, k3.n);
  const N  = k1.n * k2.n * k3.n;

  // Step 2: Cube root to recover m
  const m = intCubeRoot(M3);

  // Verify
  if (m * m * m !== M3) {
    announce('Cube root check failed — m is not a perfect cube. Possible message size issue.');
    return;
  }

  const recovered = decodeMessage(m);

  setText('hastad-N', '0x' + bigintToHex(N));
  setText('hastad-M', '0x' + bigintToHex(M3));
  setText('hastad-recovered', '0x' + bigintToHex(m));
  show('hastad-attack-steps');

  const el = document.getElementById('hastad-recovered-text') as HTMLElement;
  el.textContent = `Recovered message: "${recovered}" (hex: 0x${bigintToHex(m)})`;
  show('hastad-final-reveal');

  announceUrgent(`Attack successful. Recovered plaintext: "${recovered}" — no private key needed.`);
}

/* ════════════════════════════════════════════════════════════
   Panel 5 — Bleichenbacher PKCS#1 v1.5 Padding Oracle
   Ref: Bleichenbacher (1998), CRYPTO '98.
   ════════════════════════════════════════════════════════════ */

/** PKCS#1 v1.5 encryption padding (type 2).
 *  EM = 0x00 | 0x02 | PS (≥8 random non-zero bytes) | 0x00 | M
 *  RFC 8017 §7.2.1
 */
function pkcs1v15Pad(message: Uint8Array, k: number): Uint8Array {
  const psLen = k - message.length - 3;
  if (psLen < 8) throw new Error('Message too long for PKCS#1 v1.5 padding');

  const em = new Uint8Array(k);
  em[0] = 0x00;
  em[1] = 0x02;

  // PS: non-zero random bytes
  let idx = 2;
  while (idx < 2 + psLen) {
    const rnd = new Uint8Array(psLen - idx + 2);
    crypto.getRandomValues(rnd);
    for (const b of rnd) {
      if (b !== 0) { em[idx++] = b; }
      if (idx >= 2 + psLen) break;
    }
  }

  em[2 + psLen] = 0x00; // separator
  em.set(message, 2 + psLen + 1);
  return em;
}

/** High-performance non-constant-time PKCS#1 v1.5 unpad (demo only).
 *  Returns message bytes or null if not conformant. */
function pkcs1v15Unpad(em: Uint8Array): Uint8Array | null {
  if (em[0] !== 0x00 || em[1] !== 0x02) return null;
  // Find 0x00 separator after at least 8 bytes of PS
  for (let i = 10; i < em.length; i++) {
    if (em[i] === 0x00) return em.slice(i + 1);
  }
  return null;
}

/** Oracle: is this ciphertext PKCS#1 v1.5 conformant?
 *  Returns true iff decryption EM[0] == 0x00 and EM[1] == 0x02.
 */
function makePkcs1v15Oracle(n: bigint, d: bigint, k: number): (c: bigint) => boolean {
  return (c: bigint): boolean => {
    const m = modPow(c, d, n);
    const em = bigintToBytes(m, k);
    return em[0] === 0x00 && em[1] === 0x02;
  };
}

/* ── Bleichenbacher attack state ───────────────────────────── */
interface BbState {
  n: bigint;
  e: bigint;
  d: bigint;
  k: number;
  c: bigint;
  targetMsg: string;
  oracle: ((c: bigint) => boolean) | null;
  running: boolean;
  abortFlag: boolean;
}

const bb: BbState = {
  n: 0n, e: 0n, d: 0n, k: 0,
  c: 0n, targetMsg: '', oracle: null,
  running: false, abortFlag: false,
};

export function initBleichenbacherPanel(): void {
  (document.getElementById('bb-setup') as HTMLButtonElement)
    .addEventListener('click', bbSetup);
  (document.getElementById('bb-oracle-query') as HTMLButtonElement)
    .addEventListener('click', bbManualQuery);
  (document.getElementById('bb-run') as HTMLButtonElement)
    .addEventListener('click', bbRun);
  (document.getElementById('bb-abort') as HTMLButtonElement)
    .addEventListener('click', () => { bb.abortFlag = true; });
}

function bbSetup(): void {
  const btn = document.getElementById('bb-setup') as HTMLButtonElement;
  const lbl = btn.getAttribute('aria-label') ?? '';
  setLoading(btn, true);
  announce('Generating 128-bit RSA demo key and PKCS#1 v1.5 padded ciphertext…');

  setTimeout(() => {
    try {
      // 128-bit RSA (two 64-bit primes)
      const kp = generateRsaKeyPair(128, 65537n);
      bb.n = kp.n;
      bb.e = kp.e;
      bb.d = kp.d;
      bb.k = Math.ceil(kp.n.toString(16).length / 2); // byte length

      // Target message — short to fit in available space
      // k=16-17 bytes, so message ≤ k − 11 = 5-6 bytes
      bb.targetMsg = 'Hi!';
      const msgBytes = new TextEncoder().encode(bb.targetMsg);
      const em = pkcs1v15Pad(msgBytes, bb.k);
      const mInt = bytesToBigint(em);
      bb.c = modPow(mInt, bb.e, bb.n);

      bb.oracle = makePkcs1v15Oracle(bb.n, bb.d, bb.k);

      setText('bb-n', '0x' + bigintToHex(bb.n));
      setText('bb-e', bb.e.toString(10));
      setText('bb-target-msg', `"${bb.targetMsg}"`);
      setText('bb-ciphertext', bigintToHex(bb.c));

      // Pre-fill oracle input with the actual ciphertext
      const oracleInput = document.getElementById('bb-oracle-input') as HTMLInputElement;
      oracleInput.value = bigintToHex(bb.c);

      show('bb-setup-display');
      show('bb-oracle-card');
      show('bb-attack-card');
      announce(`Demo key ready. Modulus is ${bb.k * 8} bits (${bb.k} bytes). Target message: "${bb.targetMsg}".`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      announce(`Setup failed: ${msg}`);
    } finally {
      setLoading(btn, false, lbl);
    }
  }, 10);
}

function bbManualQuery(): void {
  if (!bb.oracle) { announce('Setup the demo first.'); return; }

  const input = document.getElementById('bb-oracle-input') as HTMLInputElement;
  let hexVal = input.value.trim().replace(/\s/g, '');
  if (!hexVal) { announce('Enter a hex value.'); return; }

  // Pad to even length
  if (hexVal.length % 2 !== 0) hexVal = '0' + hexVal;

  let c: bigint;
  try {
    c = bytesToBigint(fromHex(hexVal));
  } catch {
    announce('Invalid hex input.');
    return;
  }

  if (c >= bb.n) { announce('Ciphertext value must be less than the modulus n.'); return; }

  const conformant = bb.oracle(c);
  const log = document.getElementById('bb-oracle-result') as HTMLElement;
  const entry = document.createElement('div');
  entry.className = 'oracle-log-entry';

  const querySpan = document.createElement('span');
  querySpan.style.color = 'var(--c-text-faint)';
  querySpan.textContent = `c = 0x${hexVal.slice(0, 24)}…`;

  const resultSpan = document.createElement('span');
  resultSpan.className = conformant ? 'oracle-log-conformant' : 'oracle-log-non-conformant';
  resultSpan.textContent = conformant ? '✓ CONFORMANT' : '✗ NOT CONFORMANT';
  resultSpan.setAttribute('aria-label', conformant ? 'Conformant' : 'Not conformant');

  entry.append(querySpan, resultSpan);
  log.prepend(entry); // newest first
  announce(`Oracle result: ${conformant ? 'CONFORMANT' : 'NOT CONFORMANT'}`);
}

/**
 * Bleichenbacher's adaptive chosen-ciphertext attack.
 * Ref: Bleichenbacher (1998), Algorithm 1.
 *
 * Given: c (ciphertext), n, e, oracle(c') → bool
 * Finds: m such that m^e ≡ c (mod n), with EM[0]=0, EM[1]=2.
 *
 * Implementation notes:
 *  - B = 2^(8*(k-2)) where k = byte length of n
 *  - Initial interval M₀ = {[2B, 3B-1]}
 *  - Step 1: find s₁ ≥ ⌈n/3B⌉ s.t. oracle(c·s₁^e mod n) = true
 *  - Step 2: narrow intervals
 *  - Step 3: when |M|=1 and a=b, output the solution
 */
async function bbRun(): Promise<void> {
  if (!bb.oracle || bb.n === 0n) { announce('Setup the demo first.'); return; }
  if (bb.running) return;

  bb.running   = true;
  bb.abortFlag = false;

  const runBtn   = document.getElementById('bb-run')   as HTMLButtonElement;
  const abortBtn = document.getElementById('bb-abort') as HTMLButtonElement;
  runBtn.disabled   = true;
  abortBtn.disabled = false;

  show('bb-progress');
  hide('bb-recovered');
  const attackLog = document.getElementById('bb-attack-log') as HTMLElement;
  attackLog.textContent = '';

  announce('Bleichenbacher attack started. Searching for conformant multiplier…');

  const { n, e, k, oracle } = bb;
  const c = bb.c;

  // B = 2^(8*(k-2))
  const B  = 1n << BigInt(8 * (k - 2));
  const B2 = 2n * B;
  const B3 = 3n * B;

  let queries    = 0;
  let iterations = 0;

  const logEntry = (msg: string) => {
    const div = document.createElement('div');
    div.style.color = 'var(--c-text-muted)';
    div.style.fontSize = '0.8125rem';
    div.textContent = msg;
    attackLog.appendChild(div);
    // Auto-scroll
    attackLog.scrollTop = attackLog.scrollHeight;
  };

  // Update UI every N oracle queries
  const YIELD_EVERY  = 500;
  const MAX_QUERIES  = 600_000;

  let queryCount = 0;

  /** Calls oracle, counts queries, yields periodically. */
  const q = async (cPrime: bigint): Promise<boolean> => {
    queryCount++;
    queries++;
    const result = oracle(cPrime);
    if (queryCount % YIELD_EVERY === 0) {
      updateStats(queries, iterations, B2, B3, [[B2, B3 - 1n]]); // placeholder
      await yieldToUI();
    }
    return result;
  };

  const updateStats = (
    qs: number, iters: number,
    _B2: bigint, _B3: bigint,
    intervals: [bigint, bigint][],
  ) => {
    setText('bb-query-count', qs.toLocaleString());
    setText('bb-iteration', String(iters));

    if (intervals.length > 0) {
      const [a, b] = intervals[0];
      const size = b - a;
      const sizeBits = size > 0n ? size.toString(2).length : 0;
      setText('bb-interval-size', String(sizeBits));

      // Normalize interval for bar: position within [2B, 3B-1]
      const range = B; // 3B-1 - 2B = B-1 ≈ B
      const left  = Number((a - B2) * 1000n / range) / 10;
      const width = Math.max(0.5, Number(size * 1000n / range) / 10);
      const bar = document.getElementById('bb-interval-bar') as HTMLElement;
      bar.style.left  = `${Math.max(0, Math.min(99, left))}%`;
      bar.style.width = `${Math.max(0.3, Math.min(100 - left, width))}%`;
    }
  };

  /* ─ Interval narrowing function (Bleichenbacher 1998, Step 3) ─ */
  const narrowIntervals = (
    intervals: [bigint, bigint][],
    s: bigint,
  ): [bigint, bigint][] => {
    const result: [bigint, bigint][] = [];
    for (const [a, b] of intervals) {
      // r ranges over ceil((a*s - 3B+1)/n) .. floor((b*s - 2B)/n)
      const rMin = ceilDiv(a * s - B3 + 1n, n);
      const rMax = (b * s - B2) / n; // floor
      for (let r = rMin; r <= rMax; r = r + 1n) {
        const newA = bigintMax(a, ceilDiv(B2 + r * n, s));
        const newB = bigintMin(b, (B3 - 1n + r * n) / s);
        if (newA <= newB) {
          result.push([newA, newB]);
        }
      }
    }
    // Merge overlapping intervals
    result.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
    const merged: [bigint, bigint][] = [];
    for (const iv of result) {
      if (merged.length === 0) { merged.push(iv); continue; }
      const last = merged[merged.length - 1];
      if (iv[0] <= last[1] + 1n) {
        last[1] = bigintMax(last[1], iv[1]);
      } else {
        merged.push(iv);
      }
    }
    return merged;
  };

  try {
    /* ── Step 1: Find s₁ ≥ ⌈n/3B⌉ s.t. oracle(c*s^e mod n) = true ── */
    let s = ceilDiv(n, B3);
    logEntry(`Step 1: searching for initial s₁ ≥ ${s.toString().slice(0, 12)}…`);

    while (!(await q(c * modPow(s, e, n) % n))) {
      s = s + 1n;
      if (queries > MAX_QUERIES || bb.abortFlag) break;
    }

    if (bb.abortFlag || queries > MAX_QUERIES) {
      logEntry(`Aborted after ${queries.toLocaleString()} oracle queries.`);
      announce('Attack aborted.');
      return;
    }

    logEntry(`Found s₁ = ${s} after ${queries.toLocaleString()} queries.`);
    iterations++;

    let intervals: [bigint, bigint][] = [[B2, B3 - 1n]];
    intervals = narrowIntervals(intervals, s);
    updateStats(queries, iterations, B2, B3, intervals);

    /* ── Steps 2 & 3: Narrow until single point ── */
    while (true) {
      if (bb.abortFlag || queries > MAX_QUERIES) {
        logEntry(`Aborted/limited after ${queries.toLocaleString()} queries.`);
        announce('Attack aborted or query limit reached.');
        break;
      }

      if (intervals.length === 1 && intervals[0][0] === intervals[0][1]) {
        // Solution found!
        const m = intervals[0][0];
        showRecovery(m, k);
        logEntry(`✓ Solution found after ${queries.toLocaleString()} queries, ${iterations} iterations.`);
        announceUrgent(`Bleichenbacher attack succeeded. Recovered plaintext after ${queries.toLocaleString()} oracle queries.`);
        break;
      }

      iterations++;

      if (intervals.length > 1) {
        /* Step 2a: Linear search for next conformant s > previous s */
        s = s + 1n;
        while (!(await q(c * modPow(s, e, n) % n))) {
          s = s + 1n;
          if (queries > MAX_QUERIES || bb.abortFlag) break;
        }
      } else {
        /* Step 2c: Use tighter bounds to find r and s */
        const [a, b] = intervals[0];
        let r = ceilDiv(2n * (b * s - B2), n);
        let found = false;

        while (!found) {
          const sMin = ceilDiv(B2 + r * n, b);
          const sMax = (B3 - 1n + r * n) / a;

          for (let si = sMin; si <= sMax; si = si + 1n) {
            if (await q(c * modPow(si, e, n) % n)) {
              s = si;
              found = true;
              break;
            }
            if (queries > MAX_QUERIES || bb.abortFlag) break;
          }
          if (!found) r = r + 1n;
          if (queries > MAX_QUERIES || bb.abortFlag) break;
        }
      }

      if (queries > MAX_QUERIES || bb.abortFlag) break;

      intervals = narrowIntervals(intervals, s);
      updateStats(queries, iterations, B2, B3, intervals);

      if (iterations % 10 === 0) {
        const [a, b] = intervals[0];
        logEntry(`Iter ${iterations}: queries=${queries.toLocaleString()}, s=${s}, interval size=${(b - a).toString(2).length} bits`);
      }
    }
  } finally {
    bb.running        = false;
    runBtn.disabled   = false;
    abortBtn.disabled = true;
  }
}

function showRecovery(m: bigint, k: number): void {
  const em = bigintToBytes(m, k);
  const unpadded = pkcs1v15Unpad(em);
  const hex = bigintToHex(m);

  let text = `Recovered (raw bigint): 0x${hex}`;
  if (unpadded) {
    const str = new TextDecoder().decode(unpadded);
    text = `Recovered plaintext: "${str}" (after PKCS#1 v1.5 unpadding)`;
  }

  const textEl = document.getElementById('bb-recovered-text') as HTMLElement;
  textEl.textContent = text;

  const hexEl = document.getElementById('bb-recovered-hex') as HTMLElement;
  hexEl.textContent = `0x${hex}`;

  show('bb-recovered');
  setText('bb-interval-size', '0');
}

/* ── Helpers ────────────────────────────────────────────────── */
function bigintMax(a: bigint, b: bigint): bigint { return a > b ? a : b; }
function bigintMin(a: bigint, b: bigint): bigint { return a < b ? a : b; }

/** Yield control back to the browser event loop. */
function yieldToUI(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 0));
}
