/**
 * determinism.ts — Side-by-side textbook vs OAEP contrast (Panel 1).
 *
 * Encrypts the same plaintext twice with textbook RSA and twice with
 * RSA-OAEP, then renders byte-by-byte diffs so the user can see at
 * a glance that determinism is the bug and randomization is the fix.
 */

import { generateRsaKeyPair, modPow, encodeMessage } from './textbook.js';
import { announce, show, setLoading, bigintToBytes } from './ui.js';

const SHOW_BYTES = 16; // first/last bytes shown side-by-side

export function initDeterminismPanel(): void {
  const btn = document.getElementById('det-run') as HTMLButtonElement | null;
  if (!btn) return;
  btn.addEventListener('click', runContrast);
}

async function runContrast(): Promise<void> {
  const btn = document.getElementById('det-run') as HTMLButtonElement;
  const lbl = btn.getAttribute('aria-label') ?? '';
  setLoading(btn, true);
  announce('Running textbook vs OAEP side-by-side contrast…');

  try {
    const plaintext = 'Same plaintext twice';
    const pt = new TextEncoder().encode(plaintext);

    // — Textbook side: small key for visibility (256-bit modulus is plenty for SHOW_BYTES) —
    const tbKey = generateRsaKeyPair(256, 65537n);
    const m = encodeMessage(plaintext);
    if (m >= tbKey.n) throw new Error('plaintext too large for textbook demo key');
    const tbC1 = modPow(m, tbKey.e, tbKey.n);
    const tbC2 = modPow(m, tbKey.e, tbKey.n);
    const tbBytes1 = bigintToBytes(tbC1, 32);
    const tbBytes2 = bigintToBytes(tbC2, 32);

    // — OAEP side: real 2048-bit WebCrypto —
    const kp = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      false,
      ['encrypt', 'decrypt'],
    ) as CryptoKeyPair;
    const [ct1, ct2] = await Promise.all([
      crypto.subtle.encrypt({ name: 'RSA-OAEP' }, kp.publicKey, pt),
      crypto.subtle.encrypt({ name: 'RSA-OAEP' }, kp.publicKey, pt),
    ]);
    const oaep1 = new Uint8Array(ct1);
    const oaep2 = new Uint8Array(ct2);

    renderBytes('det-tb-ct1', tbBytes1, tbBytes2, 'tb');
    renderBytes('det-tb-ct2', tbBytes2, tbBytes1, 'tb');
    renderBytes('det-oaep-ct1', oaep1.subarray(0, SHOW_BYTES * 2), oaep2.subarray(0, SHOW_BYTES * 2), 'oaep');
    renderBytes('det-oaep-ct2', oaep2.subarray(0, SHOW_BYTES * 2), oaep1.subarray(0, SHOW_BYTES * 2), 'oaep');

    const tbDiffs   = countDiffs(tbBytes1, tbBytes2);
    const oaepDiffs = countDiffs(oaep1.subarray(0, SHOW_BYTES * 2), oaep2.subarray(0, SHOW_BYTES * 2));

    const tbSummary   = document.getElementById('det-tb-summary')   as HTMLElement;
    const oaepSummary = document.getElementById('det-oaep-summary') as HTMLElement;
    tbSummary.innerHTML   = `<strong>${tbDiffs} of ${tbBytes1.length} bytes differ.</strong> Same input → identical ciphertext, every time. An attacker who knows a candidate plaintext just checks the ciphertext.`;
    oaepSummary.innerHTML = `<strong>${oaepDiffs} of ${SHOW_BYTES * 2} bytes differ.</strong> Same input → completely different ciphertext. IND-CPA secure: the attacker learns nothing from comparing ciphertexts.`;

    show('det-contrast-grid');
    announce(`Contrast complete. Textbook: ${tbDiffs} of ${tbBytes1.length} bytes differ. OAEP: ${oaepDiffs} of ${SHOW_BYTES * 2} bytes differ.`);
  } catch (err: unknown) {
    announce(`Contrast failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    setLoading(btn, false, lbl);
  }
}

function countDiffs(a: Uint8Array, b: Uint8Array): number {
  let n = 0;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) if (a[i] !== b[i]) n++;
  return n;
}

function renderBytes(id: string, primary: Uint8Array, other: Uint8Array, mode: 'tb' | 'oaep'): void {
  const el = document.getElementById(id) as HTMLElement;
  el.textContent = '';
  const len = primary.length;
  for (let i = 0; i < len; i++) {
    const cell = document.createElement('span');
    cell.className = 'det-byte';
    const p = primary[i];
    const o = other[i] ?? -1;
    const differs = p !== o;
    if (mode === 'oaep' && differs) cell.classList.add('diff');
    if (mode === 'tb'   && !differs) cell.classList.add('same-bad');
    cell.textContent = p.toString(16).padStart(2, '0');
    el.appendChild(cell);
  }
}
