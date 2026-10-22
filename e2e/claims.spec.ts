import { expect, test, type Page } from '@playwright/test';

/**
 * Functional claims gate.
 *
 * The a11y spec proves the page is reachable; this one proves the page is
 * TRUE. Every headline verdict, counter and failure path this lab advertises
 * is driven in a real browser and checked against numbers read back out of the
 * DOM and re-derived here independently (modular exponentiation, CRT, integer
 * cube root, byte diffs). Where the page prints a computed value, the value is
 * recomputed from the page's OWN published inputs rather than compared to a
 * literal, so a wrong computation cannot pass by matching a hardcoded string.
 */

/* ── DOM readers ───────────────────────────────────────────── */

async function textOf(page: Page, sel: string): Promise<string> {
  return ((await page.locator(sel).textContent()) ?? '').trim();
}

/** Parse a bigint printed by the page: decimal, or 0x-prefixed hex. */
function bigOf(raw: string): bigint {
  const s = raw.trim().replace(/[\s,_]/g, '');
  if (/^0x[0-9a-f]+$/i.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  throw new Error(`not a bigint: ${JSON.stringify(raw)}`);
}

/** Parse a hex string printed WITHOUT a 0x prefix. */
function hexOf(raw: string): bigint {
  const s = raw.trim().replace(/[\s,_]/g, '').replace(/^0x/i, '');
  if (!/^[0-9a-f]+$/i.test(s)) throw new Error(`not hex: ${JSON.stringify(raw)}`);
  return BigInt('0x' + s);
}

/** First number in a string, tolerating thousands separators and decimals. */
function numOf(raw: string): number {
  const m = raw.replace(/,/g, '').match(/-?\d+(?:\.\d+)?/);
  if (!m) throw new Error(`no number in: ${JSON.stringify(raw)}`);
  return Number(m[0]);
}

/* ── Independent crypto re-implementations ─────────────────── */

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function extGcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  let [oldR, r] = [a, b];
  let [oldS, s] = [1n, 0n];
  let [oldT, t] = [0n, 1n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return [oldR, oldS, oldT];
}

function modInverse(a: bigint, m: bigint): bigint {
  const [g, s] = extGcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error('no inverse');
  return ((s % m) + m) % m;
}

/** CRT over three pairwise-coprime moduli. */
function crt3(a1: bigint, n1: bigint, a2: bigint, n2: bigint, a3: bigint, n3: bigint): bigint {
  const N = n1 * n2 * n3;
  const N1 = n2 * n3;
  const N2 = n1 * n3;
  const N3 = n1 * n2;
  const x =
    (a1 * N1 * modInverse(N1, n1) + a2 * N2 * modInverse(N2, n2) + a3 * N3 * modInverse(N3, n3)) % N;
  return ((x % N) + N) % N;
}

/** Exact integer cube root (floor). */
function icbrt(n: bigint): bigint {
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(n.toString(2).length / 3) + 1);
  for (;;) {
    const y = (2n * x + n / (x * x)) / 3n;
    if (y >= x) break;
    x = y;
  }
  while (x * x * x > n) x--;
  return x;
}

/** UTF-8 string -> big-endian bigint, matching the app's encodeMessage. */
function encodeMessage(s: string): bigint {
  const bytes = new TextEncoder().encode(s);
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

/* ── Page helpers ──────────────────────────────────────────── */

async function openPanel(page: Page, n: number): Promise<void> {
  await page.locator(`#tab-${n}`).click();
  await expect(page.locator(`#panel-${n}`)).toBeVisible();
}

async function load(page: Page): Promise<void> {
  await page.goto('.');
  await page.waitForSelector('#main-content');
}

test('2026 paper section: caveat, §4 values, verification, and toy malleability all match the paper', async ({
  page,
}) => {
  await load(page);

  await page.locator('#oracle-without-factoring-title').scrollIntoViewIfNeeded();
  await page.locator('#tab-5').click();
  await expect(page.locator('#oracle-without-factoring')).toBeVisible();

  const sectionText = await textOf(page, '#oracle-without-factoring');
  expect(sectionText).toContain('§4.5');
  expect(sectionText).toContain('generated the key outside the HSM');
  expect(sectionText).toContain('black-box HSM');
  expect(sectionText).toContain('temporary oracle access');
  expect(sectionText).toContain('approximately 4.07 billion');

  const e = await textOf(page, '#nfs-n');
  expect(e).toContain('aa8bb728');
  expect(await textOf(page, '#nfs-t')).toContain('804fbc7e');
  expect(await textOf(page, '#nfs-s')).toContain('944678c4');

  await page.locator('#nfs-verify').click();
  const verifyStatus = await textOf(page, '#nfs-forgery-status');
  const verifyText = await textOf(page, '#nfs-forgery-text');
  expect(verifyStatus).toBe('Verified');
  expect(verifyText).toContain('s^65537 mod N = t');
  expect(verifyText).toContain('§4.5');
  expect(verifyText).toContain('black-box HSM');

  await page.locator('#nfs-toy').click();
  await expect(page.locator('#nfs-toy-result')).toBeVisible();
  const toyText = await textOf(page, '#nfs-toy-result');
  expect(toyText).toContain('σ₁');
  expect(toyText).toContain('σ₂');
  expect(toyText).toContain('σᵉ mod n');
  expect(toyText).toContain('not an implementation of √eNFS');

  const n = hexOf(await textOf(page, '#nfs-n').then((v) => v.replace(/^0x/i, '')));
  const s = hexOf(await textOf(page, '#nfs-s').then((v) => v.replace(/^0x/i, '')));
  const t = hexOf(await textOf(page, '#nfs-t').then((v) => v.replace(/^0x/i, '')));
  const forged = modPow(s, 65537n, n);
  expect(forged).toBe(t);
});

/* ══════════════════════════════════════════════════════════════
   Panel 1 — textbook RSA
   ══════════════════════════════════════════════════════════════ */

test('textbook keygen publishes a key whose own numbers satisfy the RSA identities', async ({
  page,
}) => {
  // announce() clears the live region and fills it on a later animation frame.
  // Keep that boundary observable even when a fast local browser hides it.
  await page.addInitScript(() => {
    const nextFrame = window.requestAnimationFrame.bind(window);
    window.requestAnimationFrame = (callback) => nextFrame((time) => {
      window.setTimeout(() => callback(time), 100);
    });
  });
  await load(page);
  await page.locator('#tb-gen-small').click();
  await expect(page.locator('#tb-params')).toBeVisible();

  const p = bigOf(await textOf(page, '#tb-p'));
  const q = bigOf(await textOf(page, '#tb-q'));
  const n = bigOf(await textOf(page, '#tb-n'));
  const phi = bigOf(await textOf(page, '#tb-phi'));
  const e = bigOf(await textOf(page, '#tb-e'));
  const d = bigOf(await textOf(page, '#tb-d'));

  // Re-derive every published field from p and q alone.
  expect(p).not.toBe(q);
  expect(n).toBe(p * q);
  expect(phi).toBe((p - 1n) * (q - 1n));
  expect(e).toBe(65537n);
  expect((e * d) % phi).toBe(1n);

  // The headline verdict line is derived from that same check, so it must agree.
  const verify = await textOf(page, '#tb-verify');
  expect(verify).toContain('= 1 ✓');
  expect(verify).toContain("d really is e's inverse");
  expect(verify).not.toContain('this key is broken');

  // 32-bit primes -> a 63/64-bit modulus. Announced size must match the modulus.
  await expect(page.locator('#aria-live')).toHaveText(/RSA \d+-bit key pair generated successfully\./);
  const announced = await textOf(page, '#aria-live');
  expect(announced).toMatch(/RSA \d+-bit key pair generated successfully\./);
  expect(numOf(announced)).toBe(n.toString(2).length);
});

test('textbook encrypt/decrypt round-trips and the ciphertext equals m^e mod n', async ({
  page,
}) => {
  await load(page);
  await page.locator('#tb-gen-small').click();
  await expect(page.locator('#tb-params')).toBeVisible();

  const n = bigOf(await textOf(page, '#tb-n'));
  const e = bigOf(await textOf(page, '#tb-e'));
  const d = bigOf(await textOf(page, '#tb-d'));

  const msg = 'Hi';
  await page.locator('#tb-plaintext').fill(msg);
  await page.locator('#tb-encrypt').click();
  await expect(page.locator('#tb-encrypt-result')).toBeVisible();

  const c = hexOf(await textOf(page, '#tb-ciphertext'));
  // Independent: the page's own n and e must reproduce the page's own ciphertext.
  expect(c).toBe(modPow(encodeMessage(msg), e, n));
  // And the published private exponent must undo it.
  expect(modPow(c, d, n)).toBe(encodeMessage(msg));

  await page.locator('#tb-decrypt').click();
  await expect(page.locator('#tb-decrypted')).toHaveText(msg);
});

test('textbook encryption refuses a message wider than the modulus and says so', async ({
  page,
}) => {
  await load(page);
  await page.locator('#tb-gen-small').click();
  await expect(page.locator('#tb-params')).toBeVisible();

  const n = bigOf(await textOf(page, '#tb-n'));
  const tooLong = 'A'.repeat(20); // maxlength=20; 20 bytes >> a 64-bit modulus
  expect(encodeMessage(tooLong) >= n).toBe(true);

  await page.locator('#tb-plaintext').fill(tooLong);
  await page.locator('#tb-encrypt').click();

  await expect(page.locator('#aria-live')).toContainText('Message too large for this key.');
  // The refusal quotes the real modulus width, not a placeholder.
  await expect(page.locator('#aria-live')).toContainText(
    `${n.toString(10).length} decimal digits`,
  );
  // Failure means no ciphertext was produced.
  await expect(page.locator('#tb-encrypt-result')).toBeHidden();
});

test('textbook encryption rejects an empty message', async ({ page }) => {
  await load(page);
  await page.locator('#tb-gen-small').click();
  await expect(page.locator('#tb-params')).toBeVisible();

  await page.locator('#tb-plaintext').fill('   ');
  await page.locator('#tb-encrypt').click();
  await expect(page.locator('#aria-live')).toContainText('Please enter a message to encrypt.');
  await expect(page.locator('#tb-encrypt-result')).toBeHidden();
});

test('determinism verdict: two encryptions of one message are byte-identical', async ({ page }) => {
  await load(page);
  await page.locator('#tb-gen-small').click();
  await expect(page.locator('#tb-params')).toBeVisible();

  await page.locator('#tb-plaintext').fill('Hi');
  await page.locator('#tb-determinism').click();
  await expect(page.locator('#tb-determinism-result')).toBeVisible();

  const ct1 = await textOf(page, '#tb-ct1');
  const ct2 = await textOf(page, '#tb-ct2');
  expect(ct1).toBe(ct2);
  expect(ct1).not.toBe('—');

  // The verdict is the point of the panel: identical is the FAILURE, so it is
  // rendered in the danger colour.
  await expect(page.locator('#tb-ct-match')).toHaveText('✓ YES — always identical');
  await expect(page.locator('#tb-ct-match')).toHaveCSS('color', 'rgb(248, 113, 113)'); // --c-danger
  await expect(page.locator('#aria-live')).toContainText(
    'textbook RSA is deterministic and insecure',
  );
});

test('factoring wall recovers the two real primes of the modulus it published', async ({ page }) => {
  await load(page);
  await expect(page.locator('#tb-factor-card')).toBeVisible();
  // Nothing is claimed until the user asks.
  await expect(page.locator('#tb-factor-result')).toBeHidden();

  /** Press "Factor", read back the verdict, and check it against the n on screen. */
  const factorOnce = async (prevFound: string): Promise<bigint> => {
    await page.locator('#tb-factor-run').click();
    const n = bigOf(await textOf(page, '#tb-factor-n'));
    expect(n.toString(2).length).toBeGreaterThan(30);

    // Regression guard: the result must be VISIBLE, not written and re-hidden.
    await expect(page.locator('#tb-factor-result')).toBeVisible({ timeout: 30_000 });
    await expect.poll(() => textOf(page, '#tb-factor-found'), { timeout: 30_000 }).not.toBe(
      prevFound,
    );

    const found = await textOf(page, '#tb-factor-found');
    expect(found).toContain('Factored!');
    const m = found.match(/^Factored! n = (\d+) × (\d+)$/);
    expect(m, `unexpected verdict: ${found}`).not.toBeNull();
    const p = BigInt(m![1]);
    const q = BigInt(m![2]);

    // The two factors it claims must multiply back to the n it was shown, and
    // that n must still be the one on screen — the readout and the verdict have
    // to describe the same number.
    expect(p * q).toBe(n);
    expect(bigOf(await textOf(page, '#tb-factor-n'))).toBe(n);
    expect(p).toBeGreaterThan(1n);
    expect(q).toBeGreaterThan(1n);
    // Trial division walks upward from 3, so the reported p is the smaller factor.
    expect(p <= q).toBe(true);

    const detail = await textOf(page, '#tb-factor-detail');
    // The trial count must be consistent with where the divisor was found:
    // trials counts the /2 probe plus every odd d from 3 up to and including p.
    const trials = numOf(detail);
    expect(trials).toBe(Number((p - 3n) / 2n) + 2);
    // And the wall it contrasts against: the search only had to reach floor(sqrt(n)).
    const sqrtClaim = BigInt(detail.match(/√n ≈ ([\d,]+)/)![1].replace(/,/g, ''));
    expect(sqrtClaim * sqrtClaim <= n && (sqrtClaim + 1n) ** 2n > n).toBe(true);
    expect(detail).toContain('recomputes φ(n) and the private key d');
    expect(detail).toContain('the size of n is the whole defense');
    return n;
  };

  const first = await factorOnce('—');
  // Pressing again must draw a FRESH modulus and factor that one instead.
  const second = await factorOnce(await textOf(page, '#tb-factor-found'));
  expect(second).not.toBe(first);
});

test('textbook-vs-OAEP contrast: zero bytes differ for textbook, nearly all for OAEP', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await load(page);
  // Results are not on screen before the run.
  await expect(page.locator('#det-contrast-grid')).toBeHidden();

  await page.locator('#det-run').click();
  await expect(page.locator('#det-contrast-grid')).toBeVisible({ timeout: 60_000 });

  const tbSummary = await textOf(page, '#det-tb-summary');
  const oaepSummary = await textOf(page, '#det-oaep-summary');
  const tbDiffs = numOf(tbSummary);
  const oaepDiffs = numOf(oaepSummary);

  // Headline claims.
  expect(tbSummary).toMatch(/^0 of 32 bytes differ\./);
  expect(tbDiffs).toBe(0);
  expect(oaepDiffs).toBeGreaterThanOrEqual(28); // 32 random bytes; collisions are 1/256 each
  expect(oaepDiffs).toBeLessThanOrEqual(32);

  // The rendered byte grids must agree with the counters above them.
  const tbRow1 = await page.locator('#det-tb-ct1 .det-byte').allTextContents();
  const tbRow2 = await page.locator('#det-tb-ct2 .det-byte').allTextContents();
  expect(tbRow1).toHaveLength(32);
  expect(tbRow1.join('')).toBe(tbRow2.join(''));
  expect(await page.locator('#det-tb-ct1 .det-byte.same-bad').count()).toBe(32 - tbDiffs);

  const oaepRow1 = await page.locator('#det-oaep-ct1 .det-byte').allTextContents();
  const oaepRow2 = await page.locator('#det-oaep-ct2 .det-byte').allTextContents();
  expect(oaepRow1).toHaveLength(32);
  expect(oaepRow1.join('')).not.toBe(oaepRow2.join(''));
  let handCounted = 0;
  for (let i = 0; i < 32; i++) if (oaepRow1[i] !== oaepRow2[i]) handCounted++;
  expect(handCounted).toBe(oaepDiffs);
  expect(await page.locator('#det-oaep-ct1 .det-byte.diff').count()).toBe(oaepDiffs);
});

/* ══════════════════════════════════════════════════════════════
   Panel 2 — RSA-OAEP
   ══════════════════════════════════════════════════════════════ */

test('OAEP encrypt/decrypt round-trips through a real 2048-bit WebCrypto key', async ({ page }) => {
  test.setTimeout(90_000);
  await load(page);
  await openPanel(page, 2);

  await page.locator('#oaep-gen-2048').click();
  await expect(page.locator('#oaep-2048-timing')).toBeVisible({ timeout: 60_000 });
  expect(numOf(await textOf(page, '#oaep-2048-kg-time'))).toBeGreaterThanOrEqual(0);

  const plaintext = 'Round-trip me, OAEP.';
  await page.locator('#oaep-plaintext').fill(plaintext);
  await page.locator('#oaep-encrypt-2048').click();
  await expect(page.locator('#oaep-encrypt-result')).toBeVisible({ timeout: 30_000 });

  // A 2048-bit RSA ciphertext is exactly 256 bytes, whatever the message length.
  const b64 = await textOf(page, '#oaep-ciphertext');
  const ctBytes = Buffer.from(b64, 'base64');
  expect(ctBytes.length).toBe(2048 / 8);

  await page.locator('#oaep-decrypt-2048').click();
  await expect(page.locator('#oaep-decrypt-output')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#oaep-decrypt-output')).toHaveClass(/result-box-success/);
  await expect(page.locator('#oaep-decrypt-status')).toContainText('✓ Decryption successful');
  // The recovered text is the verdict: it must be the message, not a placeholder.
  await expect(page.locator('#oaep-decrypt-text')).toHaveText(plaintext);
});

test('OAEP refuses a plaintext past the k-2hLen-2 limit and names the limit', async ({ page }) => {
  test.setTimeout(90_000);
  await load(page);
  await openPanel(page, 2);

  await page.locator('#oaep-gen-2048').click();
  await expect(page.locator('#oaep-2048-timing')).toBeVisible({ timeout: 60_000 });

  // 2048/8 - 66 = 190 bytes is the documented ceiling; go one past it.
  await page.locator('#oaep-plaintext').fill('x'.repeat(191));
  await page.locator('#oaep-encrypt-2048').click();

  await expect(page.locator('#aria-live')).toContainText(
    'Message too long. Maximum 190 bytes for 2048-bit key with SHA-256.',
  );
  await expect(page.locator('#oaep-encrypt-result')).toBeHidden();
});

test('OAEP randomization verdict: same plaintext, different ciphertext', async ({ page }) => {
  test.setTimeout(90_000);
  await load(page);
  await openPanel(page, 2);

  await page.locator('#oaep-gen-2048').click();
  await expect(page.locator('#oaep-2048-timing')).toBeVisible({ timeout: 60_000 });
  await page.locator('#oaep-plaintext').fill('Same message, twice.');
  await page.locator('#oaep-encrypt-2048').click();
  await expect(page.locator('#oaep-encrypt-result')).toBeVisible({ timeout: 30_000 });

  await page.locator('#oaep-randomize').click();
  await expect(page.locator('#oaep-randomize-result')).toBeVisible({ timeout: 30_000 });

  const ct1 = await textOf(page, '#oaep-ct1-short');
  const ct2 = await textOf(page, '#oaep-ct2-short');
  expect(ct1).not.toBe('—');
  expect(ct1).not.toBe(ct2);
  await expect(page.locator('#oaep-ct-match')).toHaveText('✓ NO — fresh randomized encryption');
  await expect(page.locator('#aria-live')).toContainText(
    'fresh OAEP randomness produced different ciphertexts for the same plaintext',
  );
});

test('OAEP avalanche counter matches the bytes it actually highlighted', async ({ page }) => {
  await load(page);
  await openPanel(page, 2);

  const cells = page.locator('#oaep-hl-block .oaep-hl-byte');
  await expect(cells).toHaveCount(24);
  const before = await cells.allTextContents();

  await page.locator('#oaep-hl-avalanche').click();
  await expect(page.locator('#oaep-hl-note')).toContainText('output bytes changed');

  const after = await cells.allTextContents();
  expect(after).toHaveLength(24);

  // Recount both byte changes and bit flips from the rendered hex, then check
  // every number the page printed and every cell it painted as changed.
  let handCounted = 0;
  let handCountedBits = 0;
  for (let i = 0; i < 24; i++) {
    if (before[i] !== after[i]) handCounted++;
    let xor = Number.parseInt(before[i], 16) ^ Number.parseInt(after[i], 16);
    while (xor !== 0) { handCountedBits += xor & 1; xor >>>= 1; }
  }

  const note = await textOf(page, '#oaep-hl-note');
  const m = note.match(/→ (\d+) of (\d+) output bytes changed \(~(\d+)%\); (\d+) of (\d+) output bits flipped \(~(\d+)%\)/);
  expect(m, `unexpected note: ${note}`).not.toBeNull();
  const claimed = Number(m![1]);
  const total = Number(m![2]);
  const pct = Number(m![3]);
  const claimedBits = Number(m![4]);
  const totalBits = Number(m![5]);
  const bitPct = Number(m![6]);

  expect(total).toBe(24);
  expect(claimed).toBe(handCounted);
  expect(pct).toBe(Math.round((claimed / total) * 100));
  expect(claimedBits).toBe(handCountedBits);
  expect(totalBits).toBe(192);
  expect(bitPct).toBe(Math.round((claimedBits / totalBits) * 100));
  expect(await page.locator('#oaep-hl-block .oaep-hl-byte.changed').count()).toBe(claimed);
  // One flipped input bit should alter most bytes and roughly half the bits.
  expect(claimed).toBeGreaterThanOrEqual(18);
  expect(claimedBits).toBeGreaterThanOrEqual(48);
  expect(claimedBits).toBeLessThanOrEqual(144);
  await expect(page.locator('#aria-live')).toContainText(
    `${claimed} of ${total} output bytes changed`,
  );
});

/* ══════════════════════════════════════════════════════════════
   Panel 3 — RSA-PSS
   ══════════════════════════════════════════════════════════════ */

test('PSS accepts the original message and rejects the tampered one, with reasons', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await load(page);
  await openPanel(page, 3);

  await page.locator('#pss-gen').click();
  await expect(page.locator('#pss-sign-section')).toBeVisible({ timeout: 60_000 });

  const msg = 'Authenticity is the whole point.';
  await page.locator('#pss-message').fill(msg);
  await page.locator('#pss-sign').click();
  await expect(page.locator('#pss-signature-result')).toBeVisible({ timeout: 30_000 });

  // A 2048-bit RSA-PSS signature is exactly 256 bytes.
  const sig = Buffer.from(await textOf(page, '#pss-signature'), 'base64');
  expect(sig.length).toBe(256);

  // Success path.
  await page.locator('#pss-verify-ok').click();
  await expect(page.locator('#pss-verify-output')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#pss-verify-output')).toHaveClass(/result-box-success/);
  await expect(page.locator('#pss-verify-status')).toHaveText('Signature valid');
  await expect(page.locator('#pss-verify-icon')).toHaveText('✓');
  await expect(page.locator('#pss-verify-text')).toHaveText(`Message verified: "${msg}"`);

  // Tamper path — must flip to failure AND state why.
  await page.locator('#pss-verify-tampered').click();
  await expect(page.locator('#pss-verify-status')).toHaveText('Signature invalid', {
    timeout: 30_000,
  });
  await expect(page.locator('#pss-verify-output')).toHaveClass(/result-box-error/);
  await expect(page.locator('#pss-verify-icon')).toHaveText('✗');
  const why = await textOf(page, '#pss-verify-text');
  expect(why).toContain(`"${msg} (tampered)"`);
  expect(why).toContain('PSS correctly detected modification');
  expect(why).not.toContain('Unexpected');
  await expect(page.locator('#aria-live')).toContainText(
    'Signature correctly rejected — tampered message detected.',
  );
});

test('textbook, OAEP and PSS evidence retires when its key or message changes', async ({
  page,
}) => {
  test.setTimeout(240_000);
  await load(page);

  // Textbook ciphertext, decryption and determinism all belong to one key and
  // one input. Neither an edit nor a fresh key may leave them on screen.
  await page.locator('#tb-gen-small').click();
  await expect(page.locator('#tb-gen-small')).toBeEnabled();
  await page.locator('#tb-plaintext').fill('Hi');
  await page.locator('#tb-encrypt').click();
  await page.locator('#tb-decrypt').click();
  await page.locator('#tb-determinism').click();
  await expect(page.locator('#tb-encrypt-result')).toBeVisible();
  await expect(page.locator('#tb-decrypt-section')).toBeVisible();
  await expect(page.locator('#tb-determinism-result')).toBeVisible();
  await page.locator('#tb-plaintext').fill('Ho');
  await expect(page.locator('#tb-encrypt-result')).toBeHidden();
  await expect(page.locator('#tb-decrypt-section')).toBeHidden();
  await expect(page.locator('#tb-determinism-result')).toBeHidden();
  await page.locator('#tb-encrypt').click();
  await expect(page.locator('#tb-encrypt-result')).toBeVisible();
  await page.locator('#tb-gen-small').click();
  await expect(page.locator('#tb-encrypt-result')).toBeHidden();
  await expect(page.locator('#tb-decrypt-section')).toBeHidden();
  await expect(page.locator('#tb-gen-small')).toBeEnabled();

  // WebCrypto does not expose its OAEP seed. The diagram is explicitly a
  // separate valid encoding, and it too disappears with the source evidence.
  await openPanel(page, 2);
  const oaepPanel = await textOf(page, '#panel-2');
  expect(oaepPanel).toContain('separate, freshly randomized RFC 8017 encoding');
  expect(oaepPanel).not.toContain('actual bytes from that operation');
  await page.locator('#oaep-gen-2048').click();
  await expect(page.locator('#oaep-encrypt-2048')).toBeEnabled({ timeout: 60_000 });
  await page.locator('#oaep-plaintext').fill('bound OAEP evidence');
  await page.locator('#oaep-encrypt-2048').click();
  await expect(page.locator('#oaep-encrypt-result')).toBeVisible();
  await page.locator('#oaep-decrypt-2048').click();
  await expect(page.locator('#oaep-decrypt-output')).toBeVisible();
  await page.locator('#oaep-randomize').click();
  await expect(page.locator('#oaep-randomize-result')).toBeVisible();
  await page.locator('#oaep-plaintext').fill('edited OAEP evidence');
  await expect(page.locator('#oaep-encrypt-result')).toBeHidden();
  await expect(page.locator('#oaep-decrypt-card')).toBeHidden();
  await expect(page.locator('#oaep-randomize-card')).toBeHidden();
  await expect(page.locator('#oaep-decrypt-2048')).toBeDisabled();
  await page.locator('details.oaep-details summary').click();
  await page.locator('[data-oaep-field="maskedDB"]').first().focus();
  await expect(page.locator('#oaep-tooltip-bytes')).toContainText('fresh, independent valid encoding');
  await page.locator('#oaep-encrypt-2048').click();
  await expect(page.locator('#oaep-encrypt-result')).toBeVisible();
  await page.locator('#oaep-gen-2048').click();
  await expect(page.locator('#oaep-encrypt-result')).toBeHidden();
  await expect(page.locator('#oaep-decrypt-card')).toBeHidden();
  await expect(page.locator('#oaep-gen-2048')).toBeEnabled({ timeout: 60_000 });

  // PSS signatures and their independently salted diagram are bound to both
  // the signing key and exact textarea contents.
  await openPanel(page, 3);
  const pssPanel = await textOf(page, '#panel-3');
  expect(pssPanel).toContain('separate, freshly salted RFC 8017 encoding');
  expect(pssPanel).not.toContain('actual bytes from that signature');
  await page.locator('#pss-gen').click();
  await expect(page.locator('#pss-sign-section')).toBeVisible({ timeout: 60_000 });
  await page.locator('#pss-message').fill('bound PSS evidence');
  await page.locator('#pss-sign').click();
  await expect(page.locator('#pss-signature-result')).toBeVisible();
  await page.locator('#pss-verify-ok').click();
  await expect(page.locator('#pss-verify-output')).toBeVisible();
  await page.locator('#pss-message').dispatchEvent('input');
  await expect(page.locator('#pss-signature-result')).toBeVisible();
  await page.locator('#pss-message').fill('edited PSS evidence');
  await expect(page.locator('#pss-signature-result')).toBeHidden();
  await expect(page.locator('#pss-verify-card')).toBeHidden();
  await page.locator('[data-pss-field="maskedDB"]').first().focus();
  await expect(page.locator('#pss-tooltip-bytes')).toContainText('fresh, independent valid encoding');
  await page.locator('#pss-sign').click();
  await expect(page.locator('#pss-signature-result')).toBeVisible();
  await page.locator('#pss-gen').click();
  await expect(page.locator('#pss-signature-result')).toBeHidden();
  await expect(page.locator('#pss-verify-card')).toBeHidden();
  await expect(page.locator('#pss-gen')).toBeEnabled({ timeout: 60_000 });
});

test('the RSA envelope copy distinguishes JWE and S/MIME from TLS 1.3 and native age', async ({
  page,
}) => {
  await load(page);
  await openPanel(page, 6);
  await expect(page.locator('#hybrid-hybrid .hybrid-card-title')).toHaveText('RSA hybrid envelope');
  const panel = await textOf(page, '#panel-6');
  expect(panel).not.toContain('Hybrid (what TLS does)');
  expect(panel).toContain('Not used for TLS 1.3 CertificateVerify');
  expect(panel).toContain('Required for RSA CertificateVerify');
  expect(panel).toContain('Static RSA key transport is gone');
  expect(panel).toContain('PSK-only and PSK-with-(EC)DHE modes also exist');
  expect(panel).not.toContain('Only ephemeral Diffie-Hellman (ECDHE) allowed');
});

/* ══════════════════════════════════════════════════════════════
   Panel 4 — Håstad broadcast attack
   ══════════════════════════════════════════════════════════════ */

test('Håstad: broadcast ciphertexts, CRT product and cube root all check out', async ({ page }) => {
  test.setTimeout(90_000);
  await load(page);
  await openPanel(page, 4);

  await page.locator('#hastad-setup').click();
  await expect(page.locator('#hastad-recipients')).toBeVisible({ timeout: 30_000 });

  const n1 = bigOf(await textOf(page, '#hastad-n1'));
  const n2 = bigOf(await textOf(page, '#hastad-n2'));
  const n3 = bigOf(await textOf(page, '#hastad-n3'));
  // Three DISTINCT recipients — the attack is meaningless otherwise.
  expect(new Set([n1, n2, n3].map(String)).size).toBe(3);

  const msg = 'Attack';
  const m = encodeMessage(msg);
  await page.locator('#hastad-message').fill(msg);
  await page.locator('#hastad-broadcast').click();
  await expect(page.locator('#hastad-ciphertexts')).toBeVisible();

  const c1 = bigOf(await textOf(page, '#hastad-c1'));
  const c2 = bigOf(await textOf(page, '#hastad-c2'));
  const c3 = bigOf(await textOf(page, '#hastad-c3'));
  // Independent: e=3 textbook RSA under each published modulus.
  expect(c1).toBe(modPow(m, 3n, n1));
  expect(c2).toBe(modPow(m, 3n, n2));
  expect(c3).toBe(modPow(m, 3n, n3));

  await page.locator('#hastad-attack').click();
  await expect(page.locator('#hastad-attack-steps')).toBeVisible();

  const N = bigOf(await textOf(page, '#hastad-N'));
  const M3 = bigOf(await textOf(page, '#hastad-M'));
  const recovered = bigOf(await textOf(page, '#hastad-recovered'));

  expect(N).toBe(n1 * n2 * n3);
  // The attack only works because m^3 never wrapped: that is the precondition
  // the panel's explanation claims, so assert it rather than trusting it.
  expect(m ** 3n < N).toBe(true);
  expect(M3).toBe(crt3(c1, n1, c2, n2, c3, n3));
  expect(M3).toBe(m ** 3n);
  expect(recovered).toBe(icbrt(M3));
  expect(recovered).toBe(m);

  await expect(page.locator('#hastad-final-reveal')).toBeVisible();
  expect(await textOf(page, '#hastad-recovered-text')).toBe(
    `Recovered message: "${msg}" (hex: 0x${m.toString(16)})`,
  );
  const why = await textOf(page, '#hastad-whatjust-text');
  expect(why).toContain(`the exact message "${msg}"`);
  expect(why).toContain('no private key');
  expect(why).toContain('never wrapped');
  await expect(page.locator('#aria-live-assertive')).toContainText(
    `Attack successful. Recovered plaintext: "${msg}" — no private key needed.`,
  );
});

test('pick-your-config: the vulnerable choice is broken, the safe choice holds', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await load(page);
  await openPanel(page, 4);

  // Vulnerable: e=3, no padding.
  await page.locator('#cfg-vulnerable').click();
  await expect(page.locator('#cfg-result')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#cfg-result')).toHaveClass(/result-box-error/);
  await expect(page.locator('#cfg-result-title')).toHaveText(
    'Your config got broken in milliseconds.',
  );
  const brokenText = await textOf(page, '#cfg-result-text');
  // The recovered plaintext must be the message the panel says it sent.
  expect(brokenText).toContain('"Hi 3x!" was recovered as "Hi 3x!"');
  expect(brokenText).not.toContain('(recovery failed)');
  expect(brokenText).toContain('without ever touching a private key');
  await expect(page.locator('#aria-live-assertive')).toContainText(
    'Vulnerable config — message recovered: "Hi 3x!".',
  );

  // Safe: e=65537 + OAEP. The SAME attack is run and must fail.
  await page.locator('#cfg-safe').click();
  await expect(page.locator('#cfg-result-title')).toHaveText(
    'Your config held. Attack math collapses.',
    { timeout: 120_000 },
  );
  await expect(page.locator('#cfg-result')).toHaveClass(/result-box-success/);
  const heldText = await textOf(page, '#cfg-result-text');
  expect(heldText).toContain('not your message');
  expect(heldText).not.toContain('unexpectedly the message');
  expect(heldText).toContain('(no perfect cube — attack fails)');
  expect(heldText).toContain('There is no common m for CRT to reconstruct.');
  await expect(page.locator('#aria-live')).toContainText(
    'Safe config — Håstad ran and failed to recover the message.',
  );
});

/* ══════════════════════════════════════════════════════════════
   Panel 5 — Bleichenbacher padding oracle
   ══════════════════════════════════════════════════════════════ */

async function bbSetup(page: Page): Promise<{ n: bigint; e: bigint; c: bigint; k: number }> {
  await openPanel(page, 5);
  await page.locator('#bb-setup').click();
  await expect(page.locator('#bb-setup-display')).toBeVisible({ timeout: 60_000 });
  const n = bigOf(await textOf(page, '#bb-n'));
  const e = bigOf(await textOf(page, '#bb-e'));
  const c = hexOf(await textOf(page, '#bb-ciphertext'));
  const k = Math.ceil(n.toString(16).length / 2);
  return { n, e, c, k };
}

test('Bleichenbacher setup publishes a usable 128-bit key and target', async ({ page }) => {
  await load(page);
  const { n, e, c } = await bbSetup(page);

  expect(n.toString(2).length).toBeGreaterThan(120);
  expect(n.toString(2).length).toBeLessThanOrEqual(128);
  expect(e).toBe(65537n);
  expect(c).toBeGreaterThan(0n);
  expect(c < n).toBe(true);
  await expect(page.locator('#bb-target-msg')).toHaveText('"Hi!"');
  await expect(page.locator('#aria-live')).toContainText('Modulus is 128 bits (16 bytes)');
  // The oracle box is pre-loaded with the real target ciphertext.
  expect(hexOf(await page.locator('#bb-oracle-input').inputValue())).toBe(c);
});

test('homomorphism demo: Enc(a)·Enc(b) really is Enc(a·b) under the live key', async ({ page }) => {
  await load(page);
  const { n, e } = await bbSetup(page);

  await page.locator('#bb-hom-run').click();
  await expect(page.locator('#bb-hom-verdict')).toHaveClass(/match/);

  const a = bigOf(await textOf(page, '#bb-hom-a'));
  const b = bigOf(await textOf(page, '#bb-hom-b'));

  // The panel truncates long hex with an ellipsis; compare on the shown prefix,
  // recomputed here from the page's own modulus and exponent.
  const shown = (s: string) => s.replace(/^0x/, '').replace(/…$/, '');
  const encA = shown(await textOf(page, '#bb-hom-enca'));
  const encB = shown(await textOf(page, '#bb-hom-encb'));
  const prod = shown(await textOf(page, '#bb-hom-prod'));
  const encAB = shown(await textOf(page, '#bb-hom-encab'));

  const hexPad = (x: bigint) => {
    const h = x.toString(16);
    return h.length % 2 === 0 ? h : '0' + h;
  };
  expect(hexPad(modPow(a, e, n)).startsWith(encA)).toBe(true);
  expect(hexPad(modPow(b, e, n)).startsWith(encB)).toBe(true);
  expect(hexPad((modPow(a, e, n) * modPow(b, e, n)) % n).startsWith(prod)).toBe(true);
  expect(hexPad(modPow(a * b, e, n)).startsWith(encAB)).toBe(true);
  // The whole claim in one line: the two right-hand columns are the same value.
  expect(prod).toBe(encAB);
  expect((modPow(a, e, n) * modPow(b, e, n)) % n).toBe(modPow(a * b, e, n));

  const verdict = await textOf(page, '#bb-hom-verdict');
  expect(verdict).toContain('✓ Identical.');
  expect(verdict).toContain(`Enc(${a}×${b}) = Enc(${a * b})`);
  expect(verdict).not.toContain('Mismatch');
});

test('the padding oracle answers CONFORMANT for the real ciphertext and NOT for a bogus one', async ({
  page,
}) => {
  await load(page);
  const { n, c } = await bbSetup(page);

  // Pre-filled with the genuine ciphertext: it decrypts to 0x00 0x02 ... .
  await page.locator('#bb-oracle-query').click();
  const newest = page.locator('#bb-oracle-result .oracle-log-entry').first();
  await expect(newest).toContainText('✓ CONFORMANT');
  await expect(newest.locator('.oracle-log-conformant')).toHaveCount(1);

  // A ciphertext of 1 decrypts to 1 — no 0x00 0x02 prefix, so the oracle says no.
  await page.locator('#bb-oracle-input').fill('01');
  await page.locator('#bb-oracle-query').click();
  const newest2 = page.locator('#bb-oracle-result .oracle-log-entry').first();
  await expect(newest2).toContainText('✗ NOT CONFORMANT');
  await expect(page.locator('#aria-live')).toContainText('Oracle result: NOT CONFORMANT');
  await expect(page.locator('#bb-oracle-result .oracle-log-entry')).toHaveCount(2);

  // Out-of-range input is refused outright rather than silently answered.
  await page.locator('#bb-oracle-input').fill(n.toString(16));
  await page.locator('#bb-oracle-query').click();
  await expect(page.locator('#aria-live')).toContainText(
    'Ciphertext value must be less than the modulus n.',
  );
  await expect(page.locator('#bb-oracle-result .oracle-log-entry')).toHaveCount(2);

  // Empty input is refused too.
  await page.locator('#bb-oracle-input').fill('');
  await page.locator('#bb-oracle-query').click();
  await expect(page.locator('#aria-live')).toContainText('Enter a hex value.');
  await expect(page.locator('#bb-oracle-result .oracle-log-entry')).toHaveCount(2);
});

test('Bleichenbacher recovers "Hi!" and proves it by re-encryption', async ({ page }) => {
  test.setTimeout(300_000);
  await load(page);
  const { n, e, c, k } = await bbSetup(page);

  await page.locator('#bb-run').click();
  await expect(page.locator('#bb-recovered')).toBeVisible({ timeout: 240_000 });

  // Headline verdict, and the reason it is trustworthy.
  const recoveredText = await textOf(page, '#bb-recovered-text');
  expect(recoveredText).toBe(
    'Recovered plaintext: "Hi!" (after PKCS#1 v1.5 unpadding, verified mᵉ mod n == c)',
  );
  expect(recoveredText).not.toContain('NOT verified');

  // Independent proof, using only public values the page printed.
  const m = hexOf(await textOf(page, '#bb-recovered-hex'));
  expect(modPow(m, e, n)).toBe(c);

  // The recovered integer must really be PKCS#1 v1.5 type-2 padding ending in "Hi!".
  const em = m.toString(16).padStart(k * 2, '0');
  expect(em.slice(0, 4)).toBe('0002');
  expect(Buffer.from(em, 'hex').subarray(-3).toString()).toBe('Hi!');

  // Counters: every one of the k bytes should be pinned down, and the grid must
  // spell out exactly the value reported above.
  const cells = page.locator('#bb-byte-row .byte-cell');
  await expect(cells).toHaveCount(k);
  expect(await page.locator('#bb-byte-row .byte-cell.known').count()).toBe(k);
  const gridHex = (await page.locator('#bb-byte-row .byte-cell-hex').allTextContents()).join('');
  expect(gridHex).toBe(em);
  const gridAscii = (await page.locator('#bb-byte-row .byte-cell-ascii').allTextContents()).join('');
  expect(gridAscii.endsWith('Hi!')).toBe(true);

  // Interval collapsed to a single point.
  await expect(page.locator('#bb-interval-size')).toHaveText('0');

  // Query counter is a real, positive, non-placeholder total that the log agrees with.
  const queries = numOf(await textOf(page, '#bb-query-count'));
  expect(queries).toBeGreaterThan(0);
  const log = await textOf(page, '#bb-attack-log');
  expect(log).toContain('Step 1: searching for initial s₁');
  expect(log).toContain('✓ Solution found and verified (mᵉ mod n == c)');
  const logMatch = log.match(/verified \(mᵉ mod n == c\) after ([\d,]+) queries, (\d+) iterations/);
  expect(logMatch, `log did not report totals: ${log}`).not.toBeNull();
  expect(Number(logMatch![1].replace(/,/g, ''))).toBe(queries);
  expect(numOf(await textOf(page, '#bb-iteration'))).toBeGreaterThan(0);

  const why = await textOf(page, '#bb-whatjust-text');
  expect(why).toContain('one bit per query');
  expect(why).toContain('No private key was used');
  expect(why).not.toContain('NOT the plaintext');
  await expect(page.locator('#aria-live-assertive')).toContainText(
    'Bleichenbacher attack succeeded.',
  );
});

test('human-oracle mode scores truthful answers and can be aborted mid-query', async ({ page }) => {
  test.setTimeout(120_000);
  await load(page);
  await bbSetup(page);

  await page.locator('#bb-run-oracle-mode').click();
  await expect(page.locator('#bb-oracle-mode')).toBeVisible();
  await expect(page.locator('#bb-om-b0')).not.toHaveText('??');

  // Answer three queries truthfully, reading the truth off the bytes the panel
  // shows us. Both counters must track exactly.
  for (let i = 1; i <= 3; i++) {
    const b0 = await textOf(page, '#bb-om-b0');
    const b1 = await textOf(page, '#bb-om-b1');
    const conformant = b0 === '00' && b1 === '02';
    await page.locator(conformant ? '#bb-om-yes' : '#bb-om-no').click();
    await expect(page.locator('#bb-om-decisions')).toHaveText(String(i));
    await expect(page.locator('#bb-om-correct')).toHaveText(String(i));
    await expect(page.locator('#bb-om-feedback')).toHaveClass(/correct/);
    await expect(page.locator('#bb-om-feedback')).toContainText('Correct —');
    await expect(page.locator('#bb-om-b0')).not.toHaveText('??');
  }

  // Query counter is live while the human drives it.
  expect(numOf(await textOf(page, '#bb-om-total'))).toBeGreaterThanOrEqual(3);
  expect(numOf(await textOf(page, '#bb-query-count'))).toBeGreaterThanOrEqual(3);

  // Abort must stop the run and say so.
  await expect(page.locator('#bb-abort')).toBeEnabled();
  await page.locator('#bb-abort').click();
  await expect(page.locator('#bb-attack-log')).toContainText('Aborted after');
  await expect(page.locator('#aria-live')).toContainText('Attack aborted.');
  await expect(page.locator('#bb-abort')).toBeDisabled();
  await expect(page.locator('#bb-run')).toBeEnabled();
});

test('one wrong oracle answer derails the attack and the page admits it', async ({ page }) => {
  test.setTimeout(300_000);
  await load(page);
  const { n, e, c } = await bbSetup(page);

  await page.locator('#bb-run-oracle-mode').click();
  await expect(page.locator('#bb-oracle-mode')).toBeVisible();
  await expect(page.locator('#bb-om-b0')).not.toHaveText('??');

  // Wait for a query whose true answer is "not conformant", then lie and say it
  // was. Answering "no" to a conformant query is merely a missed opportunity;
  // answering "yes" to a non-conformant one poisons every later constraint.
  for (let i = 0; i < 40; i++) {
    const b0 = await textOf(page, '#bb-om-b0');
    const b1 = await textOf(page, '#bb-om-b1');
    if (!(b0 === '00' && b1 === '02')) break;
    await page.locator('#bb-om-yes').click();
    await expect(page.locator('#bb-om-b0')).not.toHaveText('??');
  }
  await page.locator('#bb-om-yes').click();
  await expect(page.locator('#bb-om-feedback')).toHaveClass(/wrong/);
  await expect(page.locator('#bb-om-feedback')).toContainText(
    'Wrong answer fed back to the algorithm.',
  );
  // The scoreboard records the miss: decisions advanced, correct did not.
  const decisions = numOf(await textOf(page, '#bb-om-decisions'));
  const correct = numOf(await textOf(page, '#bb-om-correct'));
  expect(decisions).toBe(correct + 1);

  // Keep answering "conformant" to everything. The first lie already poisoned
  // the constraint set; continuing simply drives the run to its conclusion
  // without waiting on the machine's own six-figure query budget.
  for (let i = 0; i < 600; i++) {
    if (!(await page.locator('#bb-abort').isEnabled())) break;
    await page.locator('#bb-om-yes').click();
  }
  // The run must END — on a failure, not on a hang.
  await expect(page.locator('#bb-abort')).toBeDisabled({ timeout: 60_000 });

  const log = await textOf(page, '#bb-attack-log');
  const recovered = await textOf(page, '#bb-recovered-text');
  const failed =
    log.includes('No candidate intervals remain') ||
    log.includes('mᵉ mod n ≠ c') ||
    log.includes('Aborted/limited') ||
    recovered.includes('NOT verified');
  expect(failed, `attack did not report failure. log=${log} recovered=${recovered}`).toBe(true);

  // It must never claim a verified recovery off a poisoned oracle.
  const finalLog = await textOf(page, '#bb-attack-log');
  const recoveredText = await textOf(page, '#bb-recovered-text');
  expect(recoveredText).not.toContain('verified mᵉ mod n == c');
  expect(finalLog).not.toContain('✓ Solution found and verified');
  if (finalLog.includes('No candidate intervals remain')) {
    // Constraints contradicted each other: no result box at all, plus a spoken
    // explanation of what a single wrong bit did.
    await expect(page.locator('#bb-recovered')).toBeHidden();
    await expect(page.locator('#aria-live-assertive')).toContainText(
      'the oracle answers were inconsistent, so no plaintext satisfies them',
    );
  }
  if (recoveredText.includes('NOT verified')) {
    const m = hexOf(recoveredText.replace(/^.*0x/, ''));
    // The candidate really does not re-encrypt to the ciphertext.
    expect(modPow(m, e, n)).not.toBe(c);
    expect(await textOf(page, '#bb-whatjust-text')).toContain('NOT the plaintext');
  }
});

/* ══════════════════════════════════════════════════════════════
   Panel 6 — hybrid timing
   ══════════════════════════════════════════════════════════════ */

test('hybrid benchmark: projection matches its own sample, and hybrid beats RSA-only', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await load(page);
  await openPanel(page, 6);

  await page.locator('#hybrid-run').click();
  await expect(page.locator('#hybrid-results')).toBeVisible({ timeout: 120_000 });
  await expect(page.locator('#hybrid-takeaway')).toBeVisible();

  const rsaMs = numOf(await textOf(page, '#hybrid-rsa-time'));
  const aesMs = numOf(await textOf(page, '#hybrid-aes-time'));
  const hybridMs = numOf(await textOf(page, '#hybrid-hybrid-time'));

  // The headline: RSA-only for bulk data is the slow one, by a lot.
  expect(hybridMs).toBeGreaterThan(0);
  expect(aesMs).toBeGreaterThan(0);
  expect(rsaMs).toBeGreaterThan(hybridMs);
  expect(rsaMs).toBeGreaterThan(aesMs);
  expect(rsaMs / hybridMs).toBeGreaterThan(10);

  // 1 MiB / 190-byte OAEP payload = 5519 RSA operations. Stated, and used.
  const note = await textOf(page, '#hybrid-rsa-note');
  const chunks = Math.ceil((1024 * 1024) / 190);
  expect(chunks).toBe(5519);
  expect(note).toContain(`~${chunks.toLocaleString()} RSA ops`);
  const perChunk = Number(note.match(/at ([\d.]+) ms each/)![1]);
  const sampled = Number(note.match(/sampled (\d+) chunks/)![1]);
  expect(sampled).toBe(32);
  expect(perChunk).toBeGreaterThan(0);
  // The projection must be the published sample times the published chunk count,
  // not an independent guess. The per-chunk figure is printed to 2 decimals and
  // the projection is rounded to whole ms, so allow exactly that much slack and
  // no more.
  expect(rsaMs).toBeGreaterThanOrEqual((perChunk - 0.005) * chunks - 1);
  expect(rsaMs).toBeLessThanOrEqual((perChunk + 0.005) * chunks + 1);

  // The prose repeats those numbers; they must be the same numbers.
  const takeaway = await textOf(page, '#hybrid-takeaway-text');
  const speedups = takeaway.match(/about (\d+)× slower than the hybrid scheme/);
  const aesSpeedup = takeaway.match(/and (\d+)× slower than pure AES/);
  expect(speedups, takeaway).not.toBeNull();
  expect(aesSpeedup, takeaway).not.toBeNull();
  expect(Math.abs(Number(speedups![1]) - rsaMs / hybridMs)).toBeLessThan(
    Math.max(2, (rsaMs / hybridMs) * 0.05),
  );
  expect(Math.abs(Number(aesSpeedup![1]) - rsaMs / aesMs)).toBeLessThan(
    Math.max(2, (rsaMs / aesMs) * 0.05),
  );
  expect(takeaway).toContain('This RSA-OAEP/AES-GCM envelope is available in JWE and S/MIME');
  expect(takeaway).toContain('TLS 1.3 and native age');
  expect(takeaway).toContain('they do not use this RSA/AES construction');
  await expect(page.locator('#hybrid-hybrid-note')).toHaveText(
    '1 RSA wrap + 1 AES-GCM bulk = constant asymmetric cost',
  );
});

/* ══════════════════════════════════════════════════════════════
   Navigation
   ══════════════════════════════════════════════════════════════ */

test('no result region is painted before the run that fills it', async ({ page }) => {
  await load(page);
  // Regression guard. Author rules such as `.det-contrast-grid { display: grid }`
  // outrank the UA `[hidden] { display: none }`, so six result regions used to
  // render their "—" placeholders on first load and could never be hidden again.
  const leaked = await page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>('[hidden]'))
      .filter((el) => getComputedStyle(el).display !== 'none')
      .map((el) => el.id || el.className),
  );
  expect(leaked).toEqual([]);

  // Spot-check the ones that leaked, across every panel.
  for (const id of [
    '#det-contrast-grid',
    '#oaep-2048-timing',
    '#oaep-4096-timing',
    '#hastad-recipients',
    '#hybrid-results',
    '#hybrid-takeaway',
  ]) {
    await expect(page.locator(id)).toBeHidden();
  }
});

test('each tab reveals exactly one panel', async ({ page }) => {
  await load(page);
  const tabs = await page.locator(".tab-btn").count();
  expect(tabs).toBe(8);
  for (let i = 1; i <= tabs; i++) {
    await page.locator(`#tab-${i}`).click();
    await expect(page.locator(`#panel-${i}`)).toBeVisible();
    await expect(page.locator(`#tab-${i}`)).toHaveAttribute('aria-selected', 'true');
    expect(await page.locator('.panel:visible').count()).toBe(1);
    for (let j = 1; j <= tabs; j++) {
      if (j !== i) await expect(page.locator(`#panel-${j}`)).toBeHidden();
    }
  }
});


test('the Reverse-Bleichenbacher source is visible in the oracle panel with its attack-model limits', async ({ page }) => {
  await load(page);
  await page.locator('#tab-5').click();
  const card = page.locator('#reverse-bleichenbacher-research');
  await expect(card).toBeVisible();
  await expect(card.getByRole('link')).toHaveAttribute('href', 'https://eprint.iacr.org/2026/2414');
  await expect(card).toContainText('exploitable decryption oracle');
  await expect(card).toContainText('does not implement Reverse-Bleichenbacher');
});

/* Tabs 7–8: independent public arithmetic and negative fixtures. */
import { createHash } from 'node:crypto';
async function extensionValue(page:Page,id:string):Promise<bigint>{return BigInt(await textOf(page,'#'+id));}
async function faultSigned(page:Page){await load(page);await openPanel(page,7);await page.locator('#fault-generate').click();await expect(page.locator('#fault-sign')).toBeEnabled();await page.locator('#fault-sign').click();await expect(page.locator('#fault-inject')).toBeEnabled();}
function independentGcd(a:bigint,b:bigint){a=a<0n?-a:a;while(b)[a,b]=[b,a%b];return a;}
function independentOaep(encoded:Buffer):Buffer{
  if(encoded.length<66||encoded[0]!==0)throw Error('OAEP leading byte');
  const mgf=(seed:Buffer,n:number)=>{const blocks:Buffer[]=[];for(let c=0;blocks.length*32<n;c++){const counter=Buffer.alloc(4);counter.writeUInt32BE(c);blocks.push(createHash('sha256').update(seed).update(counter).digest());}return Buffer.concat(blocks).subarray(0,n);};
  const seed=Buffer.from(encoded.subarray(1,33)),db=Buffer.from(encoded.subarray(33));let mask=mgf(db,32);for(let i=0;i<32;i++)seed[i]^=mask[i];mask=mgf(seed,db.length);for(let i=0;i<db.length;i++)db[i]^=mask[i];
  if(!db.subarray(0,32).equals(createHash('sha256').update('').digest()))throw Error('OAEP hash');let i=32;while(db[i]===0)i++;if(db[i]!==1)throw Error('OAEP separator');return db.subarray(i+1);
}
test.afterEach(async({page})=>{if(process.env.MUTATION_ASSETS){const expected=JSON.parse(process.env.MUTATION_ASSETS);const loaded=await page.locator('script[type=module][src]').evaluateAll(es=>es.map(e=>new URL((e as HTMLScriptElement).src).pathname.split('/').at(-1)).sort());expect(loaded,'MUTATION_ASSET_MISMATCH loaded modules').toEqual(Object.keys(expected).sort());}if(process.env.MUTATION_ASSETS)for(const [name,hash] of Object.entries(JSON.parse(process.env.MUTATION_ASSETS))){const response=await page.request.get('assets/'+name);expect(response.ok(),'MUTATION_ASSET_MISMATCH').toBe(true);expect(createHash('sha256').update(await response.body()).digest('hex'),'MUTATION_ASSET_MISMATCH').toBe(hash);}});

test('Tab 7: verify-before-release withholds a genuinely rejected faulty signature',async({page})=>{
  await faultSigned(page);await expect(page.locator('#fault-protect')).toBeChecked();await page.locator('#fault-inject').click();await expect(page.locator('#fault-status')).toContainText('Withheld');
  await expect(page.locator('#fault-correct-check')).toHaveAttribute('data-state','pass');await expect(page.locator('#fault-bad-check')).toHaveAttribute('data-state','fail');await expect(page.locator('#fault-factor')).toBeDisabled();await expect(page.locator('#fault-result .status-chip')).toHaveClass(/status-chip-safe/);
  const N=await extensionValue(page,'fault-N'),e=await extensionValue(page,'fault-e'),f=await extensionValue(page,'fault-faulty'),EM=await extensionValue(page,'fault-EM');expect(modPow(f,e,N)).not.toBe(EM);
});

test('Tab 7: one released fault factors the actual exported RSA-2048 key',async({page})=>{
  await page.addInitScript(()=>{const original=crypto.subtle.exportKey.bind(crypto.subtle);(window as any).capturedRsa=[];crypto.subtle.exportKey=(async(...args:any[])=>{const result=await (original as any)(...args);if(args[0]==='jwk'&&result.kty==='RSA'&&result.d)(window as any).capturedRsa.push(result);return result;}) as any;});
  await faultSigned(page);const jwk=await page.evaluate(()=>(window as any).capturedRsa.at(-1));const decode=(s:string)=>BigInt('0x'+Buffer.from(s,'base64url').toString('hex'));
  await page.locator('#fault-protect').uncheck();await page.locator('#fault-bit').fill('17');await page.locator('#fault-inject').click();await expect(page.locator('#fault-factor')).toBeEnabled();await page.locator('#fault-factor').click();await expect(page.locator('#fault-status')).toContainText('Attack complete');
  const N=await extensionValue(page,'fault-N'),p=await extensionValue(page,'fault-gcd'),q=N/p,e=await extensionValue(page,'fault-e'),s=await extensionValue(page,'fault-s'),f=await extensionValue(page,'fault-faulty'),EM=await extensionValue(page,'fault-EM'),difference=(modPow(f,e,N)-EM+N)%N;
  expect(N).toBe(decode(jwk.n));expect(p).toBe(decode(jwk.p));expect(q).toBe(decode(jwk.q));expect(p>1n&&p<N&&N%p===0n).toBe(true);expect(independentGcd(difference,N)).toBe(p);expect(independentGcd(s-f,N)).toBe(p);expect(await extensionValue(page,'fault-difference')).toBe(difference);
  await expect(page.locator('#fault-jwk-check')).toHaveAttribute('data-state','pass');await expect(page.locator('#fault-result .status-chip')).toHaveClass(/status-chip-danger/);
});

test('Tab 7: valid employee keys still expose every colleague, with all fixture checks passing',async({page})=>{
  await load(page);await openPanel(page,7);await page.locator('#shared-issue').click();await expect(page.locator('#shared-factor')).toBeEnabled();
  const N=await extensionValue(page,'shared-N'),phi=await extensionValue(page,'shared-phi'),eA=await extensionValue(page,'shared-eA'),dA=await extensionValue(page,'shared-dA'),eB=await extensionValue(page,'shared-eB'),dB=await extensionValue(page,'shared-dB'),m=await extensionValue(page,'shared-message'),cB=await extensionValue(page,'shared-cB');
  expect(eA*dA%phi).toBe(1n);expect(eB*dB%phi).toBe(1n);expect(modPow(modPow(m,eA,N),dA,N)).toBe(m);expect(modPow(cB,dB,N)).toBe(m);
  for(const id of ['A-identity','A-roundtrip','B-identity','B-roundtrip'])await expect(page.locator('#shared-'+id)).toHaveAttribute('data-state','pass');
  await page.locator('#shared-factor').click();await expect(page.locator('#shared-read')).toBeEnabled();const p=await extensionValue(page,'shared-p'),q=await extensionValue(page,'shared-q');expect(p*q).toBe(N);expect(p>1n&&p<N).toBe(true);
  await page.locator('#shared-read').click();await expect(page.locator('#shared-result')).toContainText('VALID KEY — AND EVERY COLLEAGUE EXPOSED');expect(await extensionValue(page,'shared-recoveredMessage')).toBe(m);expect(modPow(cB,await extensionValue(page,'shared-recoveredDB'),N)).toBe(m);
  await expect(page.locator('#shared-mail')).toHaveText('Private memo for B');await expect(page.locator('#shared-result .status-chip')).toHaveClass(/status-chip-danger/);
  await expect(page.locator('#shared-negative')).toHaveText("Each employee's key pair is valid on its own — e·d ≡ 1 mod φ(N) and the round trip succeeds — and any one of them still decrypts every colleague's mail.");await expect(page.locator('#shared-negative')).toBeVisible();
});

test('Tab 7: public Bezout arithmetic recovers the message and independently rejects the OAEP contrast',async({page})=>{
  await load(page);await openPanel(page,7);await page.locator('#common-encrypt').click();await expect(page.locator('#common-attack')).toBeEnabled();await page.locator('#common-attack').click();await expect(page.locator('#common-status')).toContainText('Attack complete');
  const N=await extensionValue(page,'common-N'),e1=await extensionValue(page,'common-e1'),e2=await extensionValue(page,'common-e2'),X=await extensionValue(page,'common-X'),Y=await extensionValue(page,'common-Y'),c1=await extensionValue(page,'common-c1'),c2=await extensionValue(page,'common-c2');
  const pow=(c:bigint,x:bigint)=>x<0n?modPow(modInverse(c,N),-x,N):modPow(c,x,N);
  expect(X*e1+Y*e2).toBe(1n);const recovered=pow(c1,X)*pow(c2,Y)%N;expect(recovered).toBe(encodeMessage('Same memo'));expect(await extensionValue(page,'common-recovered')).toBe(recovered);await expect(page.locator('#common-result .status-chip')).toHaveClass(/status-chip-danger/);
  await page.locator('#common-oaep').click();await expect(page.locator('#common-status')).toContainText('Attack complete');
  const bad=pow(await extensionValue(page,'common-oaep1'),X)*pow(await extensionValue(page,'common-oaep2'),Y)%N;expect(await extensionValue(page,'common-recovered')).toBe(bad);expect(()=>independentOaep(Buffer.from(bad.toString(16).padStart(512,'0'),'hex'))).toThrow('OAEP');
  for(const id of ['em1','em2'])expect(independentOaep(Buffer.from((await extensionValue(page,'common-'+id)).toString(16).padStart(512,'0'),'hex')).toString()).toBe('Same memo');
  expect(await extensionValue(page,'common-em1')).not.toBe(await extensionValue(page,'common-em2'));await expect(page.locator('#common-result')).toContainText('ATTACK FAILED');await expect(page.locator('#common-result .status-chip')).toHaveClass(/status-chip-safe/);
});

test('Tab 8: one-bit-only negative fixture recovers low bytes and re-encrypts after exactly bitLength N queries',async({page})=>{
  await load(page);await openPanel(page,8);await page.locator('#parity-setup').click();await expect(page.locator('#parity-step')).toBeEnabled();const N=await extensionValue(page,'parity-N'),e=await extensionValue(page,'parity-e'),y=await extensionValue(page,'parity-y'),x=encodeMessage('One bit is enough.');
  for(let i=1;i<=16;i++){await page.locator('#parity-step').click();await expect(page.locator('#parity-count')).toHaveText(String(i));}
  const cells=page.locator('#parity-byte-row .known .byte-cell-hex');expect(await cells.count()).toBe(2);expect((await cells.allTextContents()).join('')).toBe(x.toString(16).slice(-4));
  await page.locator('#parity-run').click();await expect(page.locator('#parity-status')).toContainText('Recovered with exactly',{timeout:60000});
  const log=(await textOf(page,'#parity-bits')).split(' ');expect(log.length).toBe(N.toString(2).length);expect(log.every(b=>b==='0'||b==='1')).toBe(true);await expect(page.locator('#parity-count')).toHaveText(String(N.toString(2).length));
  const sum=log.reduce((a,b,i)=>a+(BigInt(b)<<BigInt(i)),0n),mask=1n<<BigInt(log.length);expect(((-N*sum)%mask+mask)%mask).toBe(x);expect(await extensionValue(page,'parity-recovered')).toBe(x);expect(modPow(x,e,N)).toBe(y);
  await expect(page.locator('#parity-reencrypt')).toHaveAttribute('data-state','pass');await expect(page.locator('#parity-result .status-chip')).toHaveClass(/status-chip-danger/);await expect(page.locator('#parity-plaintext')).toHaveText('One bit is enough.');
  await expect(page.locator('#parity-negative')).toHaveText('The server never returns a plaintext, only one bit, and that is enough to decrypt everything it can be sent.');await expect(page.locator('#parity-negative')).toBeVisible();
});

test('Tab 8: real-size cancellation remains partial; resume reaches 2048 verified queries',async({page})=>{
  test.setTimeout(120000);await load(page);await openPanel(page,8);await page.locator('#parity-size').selectOption('2048');await page.locator('#parity-setup').click();await expect(page.locator('#parity-step')).toBeEnabled();await page.locator('#parity-run').click();await expect.poll(async()=>Number(await textOf(page,'#parity-count'))).toBeGreaterThan(0);await page.locator('#parity-cancel').click();await expect(page.locator('#parity-status')).toContainText('Cancelled');await expect(page.locator('#parity-result')).toContainText('PARTIAL');await expect(page.locator('#parity-plaintext')).toHaveCount(0);expect(Number(await textOf(page,'#parity-count'))).toBeLessThan(2048);
  await page.locator('#parity-run').click();await expect(page.locator('#parity-status')).toContainText('Recovered with exactly',{timeout:90000});await expect(page.locator('#parity-count')).toHaveText('2048');await expect(page.locator('#parity-reencrypt')).toHaveAttribute('data-state','pass');expect(await extensionValue(page,'parity-recovered')).toBe(encodeMessage('One bit is enough.'));
});

test('Tabs 7–8: edits and fresh keys retire results, while identical inputs preserve them',async({page})=>{
  await faultSigned(page);await page.locator('#fault-inject').click();await expect(page.locator('#fault-status')).toContainText('Withheld');const before=await textOf(page,'#fault-result');await page.locator('#fault-protect').dispatchEvent('change');await page.locator('#fault-bit').dispatchEvent('input');await expect(page.locator('#fault-result')).toHaveText(before);
  await page.locator('#fault-bit').fill('1024');await expect(page.locator('#fault-result')).toBeEmpty();await page.locator('#fault-inject').click();await expect(page.locator('#fault-status')).toContainText('Bit index');await expect(page.locator('#fault-factor')).toBeDisabled();
  await page.locator('#fault-generate').click();await expect(page.locator('#fault-result')).toBeEmpty();await expect(page.locator('#fault-sign')).toBeEnabled();await expect(page.locator('#fault-inject')).toBeDisabled();
  await openPanel(page,8);await page.locator('#parity-setup').click();await expect(page.locator('#parity-step')).toBeEnabled();await page.locator('#parity-step').click();await page.locator('#parity-size').dispatchEvent('change');await page.locator('#parity-message').dispatchEvent('input');await expect(page.locator('#parity-count')).toHaveText('1');await page.locator('#parity-message').fill('edited');await expect(page.locator('#parity-count')).toHaveText('0');await expect(page.locator('#parity-result')).toBeEmpty();await expect(page.locator('#parity-step')).toBeDisabled();
});
