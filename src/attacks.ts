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
export function intCubeRoot(n: bigint): bigint {
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
export function crt3(
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

  // Pick-your-config challenge
  (document.getElementById('cfg-vulnerable') as HTMLButtonElement)
    .addEventListener('click', () => runConfigChallenge('vulnerable'));
  (document.getElementById('cfg-safe') as HTMLButtonElement)
    .addEventListener('click', () => runConfigChallenge('safe'));
}

/* ── Pick-your-config challenge ─────────────────────────────── */
async function runConfigChallenge(choice: 'vulnerable' | 'safe'): Promise<void> {
  const resultBox  = document.getElementById('cfg-result')       as HTMLElement;
  const iconEl     = document.getElementById('cfg-result-icon')  as HTMLElement;
  const titleEl    = document.getElementById('cfg-result-title') as HTMLElement;
  const textEl     = document.getElementById('cfg-result-text')  as HTMLElement;
  const message = 'Hi 3x!';

  if (choice === 'vulnerable') {
    announce('Running Håstad broadcast attack on the e=3, no-padding config you picked…');
    try {
      const keys: RsaKeyPair[] = [];
      for (let i = 0; i < 3; i++) keys.push(generateRsaKeyPair(64, 3n));
      const m = encodeMessage(message);
      for (const k of keys) {
        if (m >= k.n) {
          throw new Error('message too large for demo keys — try a shorter string');
        }
      }
      const c1 = modPow(m, 3n, keys[0].n);
      const c2 = modPow(m, 3n, keys[1].n);
      const c3 = modPow(m, 3n, keys[2].n);
      const N  = keys[0].n * keys[1].n * keys[2].n;
      const M3 = crt3(c1, keys[0].n, c2, keys[1].n, c3, keys[2].n);
      const recovered = intCubeRoot(M3);
      const valid = recovered * recovered * recovered === M3;
      const plaintext = valid ? decodeMessage(recovered) : '(recovery failed)';
      void N;

      resultBox.className = 'result-box result-box-error';
      iconEl.textContent  = '🔓';
      titleEl.textContent = 'Your config got broken in milliseconds.';
      textEl.innerHTML =
        `Your message <code>"${message}"</code> was recovered as <code>"${plaintext}"</code> without ever touching a private key. ` +
        `Three intercepted ciphertexts + CRT + a cube root. That's it. ` +
        `This is the same recipe used to break early SSL implementations and naïve IoT firmware.`;
      announceUrgent(`Vulnerable config — message recovered: "${plaintext}".`);
    } catch (err: unknown) {
      resultBox.className = 'result-box result-box-error';
      iconEl.textContent  = '⚠️';
      titleEl.textContent = 'Attack setup failed';
      textEl.textContent  = err instanceof Error ? err.message : String(err);
    }
    show('cfg-result');
    return;
  }

  // Safe path: e=65537 + OAEP. Show that the same attack mathematically fails.
  announce('Encrypting your message under three RSA-2048-OAEP recipients and attempting Håstad…');
  try {
    const recipients = await Promise.all([0, 1, 2].map(() =>
      crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: 'SHA-256',
        },
        false,
        ['encrypt', 'decrypt'],
      ) as Promise<CryptoKeyPair>,
    ));
    const pt = new TextEncoder().encode(message);
    const cts = await Promise.all(recipients.map(r =>
      crypto.subtle.encrypt({ name: 'RSA-OAEP' }, r.publicKey, pt),
    ));

    // Actually RUN Håstad on the real OAEP ciphertexts and show it fails.
    // Håstad assumes e is small (3) and the SAME integer m was exponentiated
    // under each modulus. Here e=65537 and OAEP randomizes every plaintext, so
    // we deliberately mis-apply the attack with e=3 to demonstrate the recovered
    // value is garbage — not the message.
    const moduli = recipients.map(r => spkiModulus(r.publicKey));
    const [n1, n2, n3] = await Promise.all(moduli);
    const c1 = bytesToBigint(new Uint8Array(cts[0]));
    const c2 = bytesToBigint(new Uint8Array(cts[1]));
    const c3 = bytesToBigint(new Uint8Array(cts[2]));

    let recoveredStr = '(no perfect cube — attack fails)';
    let recoveredMatches = false;
    // Guard: CRT needs pairwise-coprime moduli. Distinct RSA moduli are coprime
    // with overwhelming probability.
    if (n1 !== n2 && n1 !== n3 && n2 !== n3) {
      const M3 = crt3(c1, n1, c2, n2, c3, n3);
      const guess = intCubeRoot(M3);
      const isPerfectCube = guess * guess * guess === M3;
      if (isPerfectCube) {
        // Extraordinarily unlikely; if it happened, check it against the message.
        try {
          const recovered = decodeMessage(guess);
          recoveredMatches = recovered === message;
          recoveredStr = `"${recovered}"`;
        } catch { recoveredStr = '(non-decodable bytes)'; }
      }
    }

    resultBox.className = 'result-box result-box-success';
    iconEl.textContent  = '🛡️';
    titleEl.textContent = 'Your config held. Attack math collapses.';
    textEl.innerHTML =
      `We actually ran Håstad on your three real RSA-2048-OAEP ciphertexts: CRT-combined them and took an integer cube root. ` +
      `The result was <strong>${recoveredMatches ? 'unexpectedly the message' : 'not your message'}</strong> — recovered value: <code>${recoveredStr}</code>. ` +
      `Two things break the attack: e = 65537 (not 3) so the ciphertexts are m<sup>65537</sup>, not m<sup>3</sup>; and OAEP prepends 32 fresh random bytes per recipient, ` +
      `so the three integers that actually get exponentiated are <em>different</em>. There is no common m for CRT to reconstruct. ` +
      `This is the NIST-recommended default and what real production code should use.`;
    announce('Safe config — Håstad ran and failed to recover the message.');
    show('cfg-result');
  } catch (err: unknown) {
    resultBox.className = 'result-box result-box-error';
    iconEl.textContent  = '⚠️';
    titleEl.textContent = 'Safe path failed unexpectedly';
    textEl.textContent  = err instanceof Error ? err.message : String(err);
    show('cfg-result');
  }
}

/** Extract the RSA modulus n from a WebCrypto public key (via JWK 'n'). */
async function spkiModulus(pub: CryptoKey): Promise<bigint> {
  const jwk = await crypto.subtle.exportKey('jwk', pub);
  if (!jwk.n) throw new Error('public key has no modulus');
  // JWK 'n' is base64url of the big-endian modulus bytes.
  const b64 = jwk.n.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '='));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytesToBigint(bytes);
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

  const wj = document.getElementById('hastad-whatjust-text');
  if (wj) {
    wj.textContent =
      `You recovered the exact message "${recovered}" with no private key, using only the three public ` +
      `ciphertexts. Because e = 3 and there was no padding, the same integer m was cubed under each modulus, so ` +
      `m³ stayed smaller than n₁·n₂·n₃ and never wrapped. CRT rebuilt m³ exactly, and a plain cube root undid the ` +
      `e = 3. Padding (OAEP) or a large exponent (65537) would have broken every one of those steps.`;
  }
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
export function pkcs1v15Pad(message: Uint8Array, k: number): Uint8Array {
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

/** Non-constant-time PKCS#1 v1.5 unpad (demo only).
 *  Returns message bytes or null if not conformant.
 *
 *  RFC 8017 §7.2.2 requires EM = 0x00 || 0x02 || PS || 0x00 || M where PS is
 *  at least 8 non-zero octets. The separator scan therefore starts at index 10
 *  (2 leading bytes + 8-byte minimum PS): any 0x00 before that would mean PS is
 *  shorter than 8 bytes, i.e. non-conformant padding. We additionally verify
 *  that every octet of PS in [2, sep) is non-zero, which the earlier version
 *  skipped — a strict RFC check, not just the demo shortcut. */
export function pkcs1v15Unpad(em: Uint8Array): Uint8Array | null {
  if (em[0] !== 0x00 || em[1] !== 0x02) return null;
  // PS occupies indices [2, sep) and must be >= 8 non-zero octets (RFC 8017
  // §7.2.2). Reject if any of the first 8 PS octets is 0x00 (would make PS < 8),
  // then take the first 0x00 at or after index 10 as the separator.
  for (let j = 2; j < 10 && j < em.length; j++) {
    if (em[j] === 0x00) return null; // PS shorter than 8 bytes → non-conformant
  }
  for (let i = 10; i < em.length; i++) {
    if (em[i] === 0x00) return em.slice(i + 1);
  }
  return null;
}

/** Oracle: is this ciphertext PKCS#1 v1.5 conformant?
 *  Returns true iff decryption EM[0] == 0x00 and EM[1] == 0x02.
 */
export function makePkcs1v15Oracle(n: bigint, d: bigint, k: number): (c: bigint) => boolean {
  return (c: bigint): boolean => {
    const m = modPow(c, d, n);
    const em = bigintToBytes(m, k);
    return em[0] === 0x00 && em[1] === 0x02;
  };
}

/**
 * Headless Bleichenbacher solver (RFC-faithful, no DOM).
 *
 * This is the exact interval-narrowing algorithm the interactive panel runs,
 * factored out so it can be unit-tested against a known plaintext. Given a
 * ciphertext c, the public key (n, e), the modulus byte-length k, and a padding
 * oracle, it returns the recovered integer m with m^e ≡ c (mod n).
 *
 * Ref: Bleichenbacher (1998), Algorithm (Steps 1–4), CRYPTO '98.
 */
export function bleichenbacherAttack(
  c: bigint,
  n: bigint,
  e: bigint,
  k: number,
  oracle: (c: bigint) => boolean,
  maxQueries = 5_000_000,
): { m: bigint; queries: number } {
  const B  = 1n << BigInt(8 * (k - 2));
  const B2 = 2n * B;
  const B3 = 3n * B;
  let queries = 0;

  const query = (cPrime: bigint): boolean => {
    queries++;
    if (queries > maxQueries) throw new Error('Bleichenbacher: query budget exceeded');
    return oracle(cPrime);
  };

  const narrow = (
    intervals: [bigint, bigint][],
    s: bigint,
  ): [bigint, bigint][] => {
    const result: [bigint, bigint][] = [];
    for (const [a, b] of intervals) {
      const rMin = ceilDiv(a * s - B3 + 1n, n);
      const rMax = (b * s - B2) / n;
      for (let r = rMin; r <= rMax; r = r + 1n) {
        const newA = bigintMax(a, ceilDiv(B2 + r * n, s));
        const newB = bigintMin(b, (B3 - 1n + r * n) / s);
        if (newA <= newB) result.push([newA, newB]);
      }
    }
    result.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
    const merged: [bigint, bigint][] = [];
    for (const iv of result) {
      if (merged.length === 0) { merged.push([iv[0], iv[1]]); continue; }
      const last = merged[merged.length - 1];
      if (iv[0] <= last[1] + 1n) last[1] = bigintMax(last[1], iv[1]);
      else merged.push([iv[0], iv[1]]);
    }
    return merged;
  };

  // Step 1: find s1 >= ceil(n / 3B) with a conformant blinding.
  let s = ceilDiv(n, B3);
  while (!query(c * modPow(s, e, n) % n)) s = s + 1n;

  let intervals: [bigint, bigint][] = narrow([[B2, B3 - 1n]], s);

  // Steps 2 & 3: narrow to a single point.
  while (!(intervals.length === 1 && intervals[0][0] === intervals[0][1])) {
    if (intervals.length > 1) {
      // Step 2b: linear search for the next conformant s.
      s = s + 1n;
      while (!query(c * modPow(s, e, n) % n)) s = s + 1n;
    } else {
      // Step 2c: single interval — search r/s pairs from tighter bounds.
      const [a, b] = intervals[0];
      let r = 2n * ceilDiv(b * s - B2, n);
      let found = false;
      while (!found) {
        const sMin = ceilDiv(B2 + r * n, b);
        const sMax = (B3 - 1n + r * n) / a;
        for (let si = sMin; si <= sMax; si = si + 1n) {
          if (query(c * modPow(si, e, n) % n)) { s = si; found = true; break; }
        }
        if (!found) r = r + 1n;
      }
    }
    intervals = narrow(intervals, s);
  }

  return { m: intervals[0][0], queries };
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
  // "You are the oracle" mode
  humanOracle: boolean;
  humanDecisions: number;
  humanCorrect: number;
  pendingResolve: ((value: boolean) => void) | null;
  pendingTrue: boolean;
}

const bb: BbState = {
  n: 0n, e: 0n, d: 0n, k: 0,
  c: 0n, targetMsg: '', oracle: null,
  running: false, abortFlag: false,
  humanOracle: false,
  humanDecisions: 0, humanCorrect: 0,
  pendingResolve: null, pendingTrue: false,
};

export function initBleichenbacherPanel(): void {
  (document.getElementById('bb-setup') as HTMLButtonElement)
    .addEventListener('click', bbSetup);
  (document.getElementById('bb-oracle-query') as HTMLButtonElement)
    .addEventListener('click', bbManualQuery);
  (document.getElementById('bb-hom-run') as HTMLButtonElement | null)
    ?.addEventListener('click', bbHomomorphicDemo);
  (document.getElementById('bb-run') as HTMLButtonElement)
    .addEventListener('click', () => bbRun(false));
  (document.getElementById('bb-run-oracle-mode') as HTMLButtonElement)
    .addEventListener('click', () => bbRun(true));
  (document.getElementById('bb-abort') as HTMLButtonElement)
    .addEventListener('click', () => { bb.abortFlag = true; bbResumeFromHuman(false); });

  // Human-oracle response buttons
  (document.getElementById('bb-om-yes') as HTMLButtonElement)
    .addEventListener('click', () => bbResumeFromHuman(true));
  (document.getElementById('bb-om-no') as HTMLButtonElement)
    .addEventListener('click', () => bbResumeFromHuman(false));
  (document.getElementById('bb-om-autocomplete') as HTMLButtonElement)
    .addEventListener('click', () => {
      bb.humanOracle = false;
      hide('bb-oracle-mode');
      // Resume any pending query with the truthful answer so we don't desync.
      bbResumeFromHuman(bb.pendingTrue);
      announce('Switching to auto-complete. The machine will finish the attack.');
    });
}

/** Resume a paused query from the human oracle with their answer. */
function bbResumeFromHuman(answer: boolean): void {
  if (!bb.pendingResolve) return;
  const resolve = bb.pendingResolve;
  bb.pendingResolve = null;

  if (bb.humanOracle) {
    bb.humanDecisions++;
    const correct = answer === bb.pendingTrue;
    if (correct) bb.humanCorrect++;
    const fb = document.getElementById('bb-om-feedback') as HTMLElement;
    if (correct) {
      fb.className = 'oracle-mode-feedback correct';
      fb.textContent = answer
        ? 'Correct — those first two bytes ARE 0x00 0x02. The attack just narrowed its interval.'
        : 'Correct — those bytes are not 0x00 0x02. The attack will try the next multiplier.';
    } else {
      fb.className = 'oracle-mode-feedback wrong';
      fb.textContent = 'Wrong answer fed back to the algorithm. In real attacks the oracle is a server; one wrong answer derails the attack.';
    }
    setText('bb-om-decisions', String(bb.humanDecisions));
    setText('bb-om-correct',   String(bb.humanCorrect));
  }

  resolve(answer);
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

/** Homomorphic-lever demo: Enc(a)·Enc(b) mod n = Enc(a·b) on the real demo key.
 *  Grounds the multiplicative homomorphism the Bleichenbacher attack exploits,
 *  BEFORE the interval search — so the shrinking bar reads as consequence, not magic. */
function bbHomomorphicDemo(): void {
  if (bb.n === 0n) { announce('Set up the demo key first.'); return; }
  const { n, e } = bb;

  // Two small plaintexts whose product stays below n (trivially true here).
  const a = 42n;
  const b = 1000n;
  const encA  = modPow(a, e, n);
  const encB  = modPow(b, e, n);
  const prod  = (encA * encB) % n;      // multiply the two ciphertexts
  const encAB = modPow(a * b, e, n);    // encrypt the product directly
  const match = prod === encAB;

  const shortHex = (x: bigint) => {
    const h = bigintToHex(x);
    return '0x' + (h.length > 20 ? h.slice(0, 20) + '…' : h);
  };

  setText('bb-hom-a', a.toString(10));
  setText('bb-hom-b', b.toString(10));
  setText('bb-hom-enca', shortHex(encA));
  setText('bb-hom-encb', shortHex(encB));
  setText('bb-hom-prod', shortHex(prod));
  setText('bb-hom-encab', shortHex(encAB));

  const verdict = document.getElementById('bb-hom-verdict') as HTMLElement;
  if (match) {
    verdict.className = 'bb-hom-verdict match';
    verdict.textContent =
      `✓ Identical. Multiplying the two ciphertexts produced exactly Enc(${a}×${b}) = Enc(${a * b}) — ` +
      `without ever decrypting. That is RSA’s multiplicative homomorphism, and it is the attacker’s only lever: ` +
      `by multiplying the target c by sᵉ they force the hidden plaintext to become m×s, then read one bit of it through the oracle.`;
  } else {
    verdict.className = 'bb-hom-verdict nomatch';
    verdict.textContent = '✗ Mismatch (unexpected) — check the demo key setup.';
  }
  announce(match
    ? 'Confirmed: multiplying two ciphertexts equals encrypting the product of their plaintexts.'
    : 'Homomorphic demo mismatch (unexpected).');
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
async function bbRun(humanOracle: boolean): Promise<void> {
  if (!bb.oracle || bb.n === 0n) { announce('Setup the demo first.'); return; }
  if (bb.running) return;

  bb.running     = true;
  bb.abortFlag   = false;
  bb.humanOracle = humanOracle;
  bb.humanDecisions = 0;
  bb.humanCorrect   = 0;

  const runBtn       = document.getElementById('bb-run')              as HTMLButtonElement;
  const runHumanBtn  = document.getElementById('bb-run-oracle-mode')  as HTMLButtonElement;
  const abortBtn     = document.getElementById('bb-abort')            as HTMLButtonElement;
  runBtn.disabled      = true;
  runHumanBtn.disabled = true;
  abortBtn.disabled    = false;

  show('bb-progress');
  hide('bb-recovered');
  const attackLog = document.getElementById('bb-attack-log') as HTMLElement;
  attackLog.textContent = '';

  // Reset byte-by-byte reveal grid
  initByteRevealGrid(bb.k);

  if (humanOracle) {
    show('bb-oracle-mode');
    setText('bb-om-decisions', '0');
    setText('bb-om-correct',   '0');
    setText('bb-om-total',     '0');
    const fb = document.getElementById('bb-om-feedback') as HTMLElement;
    fb.textContent = '';
    fb.className = 'oracle-mode-feedback';
    announce('You are now the padding oracle. Click conformant or not conformant for each query.');
  } else {
    hide('bb-oracle-mode');
    announce('Bleichenbacher attack started. Searching for conformant multiplier…');
  }

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

  /** Calls oracle, counts queries, yields periodically.
   *  In humanOracle mode, pauses for the user's verdict on the first 2 bytes. */
  const q = async (cPrime: bigint): Promise<boolean> => {
    queryCount++;
    queries++;
    const truth = oracle(cPrime);

    if (bb.humanOracle) {
      setText('bb-om-total',  queries.toLocaleString());
      setText('bb-query-count', queries.toLocaleString());
      // Show the first two decrypted bytes to the human.
      const em = bigintToBytes(modPow(cPrime, bb.d, bb.n), bb.k);
      const b0 = em[0], b1 = em[1];
      const b0el = document.getElementById('bb-om-b0') as HTMLElement;
      const b1el = document.getElementById('bb-om-b1') as HTMLElement;
      b0el.textContent = b0.toString(16).padStart(2, '0');
      b1el.textContent = b1.toString(16).padStart(2, '0');
      b0el.className = 'byte-shown' + (b0 === 0x00 ? ' is-zero' : '');
      b1el.className = 'byte-shown' + (b1 === 0x02 ? ' is-two' : '');
      bb.pendingTrue = truth;
      // Yield to allow the UI to paint before awaiting.
      await yieldToUI();
      const answer = await new Promise<boolean>(resolve => {
        bb.pendingResolve = resolve;
      });
      return answer;
    }

    if (queryCount % YIELD_EVERY === 0) {
      updateStats(queries, iterations, B2, B3, [[B2, B3 - 1n]]); // placeholder
      await yieldToUI();
    }
    return truth;
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

      // Byte-by-byte reveal: any leading bytes where bytes(a)[i] == bytes(b)[i]
      // are uniquely determined.
      updateByteReveal(a, b, bb.k);
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
        let r = 2n * ceilDiv(b * s - B2, n);
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
    bb.running           = false;
    bb.humanOracle       = false;
    bb.pendingResolve    = null;
    runBtn.disabled      = false;
    runHumanBtn.disabled = false;
    abortBtn.disabled    = true;
  }
}

/* ── Byte-by-byte reveal helpers ────────────────────────────── */
function initByteRevealGrid(k: number): void {
  const row = document.getElementById('bb-byte-row');
  if (!row) return;
  row.textContent = '';
  for (let i = 0; i < k; i++) {
    const cell = document.createElement('div');
    cell.className = 'byte-cell';
    cell.id = `bb-byte-${i}`;
    const hex = document.createElement('span');
    hex.className = 'byte-cell-hex';
    hex.textContent = '??';
    const ascii = document.createElement('span');
    ascii.className = 'byte-cell-ascii';
    ascii.textContent = '·';
    cell.append(hex, ascii);
    row.appendChild(cell);
  }
}

function updateByteReveal(a: bigint, b: bigint, k: number): void {
  const aBytes = bigintToBytes(a, k);
  const bBytes = bigintToBytes(b, k);
  for (let i = 0; i < k; i++) {
    const cell = document.getElementById(`bb-byte-${i}`);
    if (!cell) continue;
    const hex = cell.querySelector('.byte-cell-hex')   as HTMLElement;
    const asc = cell.querySelector('.byte-cell-ascii') as HTMLElement;

    // Byte is known if a[0..i] == b[0..i] (all preceding bytes agree).
    let known = true;
    for (let j = 0; j <= i; j++) {
      if (aBytes[j] !== bBytes[j]) { known = false; break; }
    }
    if (known) {
      const byte = aBytes[i];
      const newHex = byte.toString(16).padStart(2, '0');
      const newAsc = byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '·';
      if (!cell.classList.contains('known')) {
        cell.classList.add('known', 'just-revealed');
        setTimeout(() => cell.classList.remove('just-revealed'), 700);
      }
      hex.textContent = newHex;
      asc.textContent = newAsc;
    }
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

  const wj = document.getElementById('bb-whatjust-text');
  if (wj) {
    const recoveredMsg = unpadded ? new TextDecoder().decode(unpadded) : null;
    wj.textContent =
      `You decrypted the ciphertext${recoveredMsg ? ` back to "${recoveredMsg}"` : ''} while only ever learning ` +
      `one bit per query: “do the first two bytes equal 0x00 0x02?” Each multiply-by-sᵉ turned the hidden ` +
      `plaintext into m×s (the homomorphic lever above), and every “conformant” answer proved m×s fell inside the ` +
      `padding window [2B, 3B−1], squeezing the interval [a, b] around m until only one value remained. No private ` +
      `key was used — just a leaky padding check. OAEP’s all-or-nothing decoding removes that one-bit leak entirely.`;
  }

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
