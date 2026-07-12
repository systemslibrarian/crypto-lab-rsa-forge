/**
 * hybrid.ts — Panel 6 hybrid-crypto timing demo.
 *
 * Times three approaches on 1 MB of random data:
 *  1. RSA-OAEP only — measured per chunk, projected to 1 MB.
 *     (You cannot actually encrypt 1 MB with RSA in any reasonable way;
 *      this is the cost a naïve implementation would pay.)
 *  2. AES-256-GCM only — single key, full payload.
 *  3. Hybrid (what TLS / S/MIME / age all do) — RSA-OAEP wraps a fresh
 *     AES key, then AES-GCM encrypts the bulk.
 */

import { announce, show, setText, setLoading } from './ui.js';

const MEGABYTE = 1024 * 1024;
const RSA_CHUNK = 190; // OAEP-SHA256 max for 2048-bit modulus
const MAX_RANDOM_VALUES_BYTES = 65_536;

export function initHybridPanel(): void {
  const btn = document.getElementById('hybrid-run') as HTMLButtonElement | null;
  if (!btn) return;
  btn.addEventListener('click', runHybrid);
}

function fillRandom(bytes: Uint8Array): void {
  for (let offset = 0; offset < bytes.length; offset += MAX_RANDOM_VALUES_BYTES) {
    crypto.getRandomValues(bytes.subarray(offset, offset + MAX_RANDOM_VALUES_BYTES));
  }
}

async function runHybrid(): Promise<void> {
  const btn = document.getElementById('hybrid-run') as HTMLButtonElement;
  const lbl = btn.getAttribute('aria-label') ?? '';
  setLoading(btn, true);
  announce('Generating 1 megabyte of random data and timing three encryption strategies…');

  try {
    const payload = new Uint8Array(MEGABYTE);
    fillRandom(payload);

    // — RSA-OAEP-2048 key (used for #1 and the wrap step of #3) —
    const rsaPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      false,
      ['encrypt', 'decrypt'],
    ) as CryptoKeyPair;

    /* ── 1. RSA-only (project from a small sample) ── */
    const sampleChunks = 32;
    const sampleBuf = payload.subarray(0, RSA_CHUNK);
    const rsaSampleT0 = performance.now();
    for (let i = 0; i < sampleChunks; i++) {
      // Re-encrypt the same buffer; OAEP randomization is internal.
      await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPair.publicKey, sampleBuf);
    }
    const rsaSampleMs = performance.now() - rsaSampleT0;
    const totalChunksFor1MB = Math.ceil(MEGABYTE / RSA_CHUNK);
    const rsaProjectedMs = (rsaSampleMs / sampleChunks) * totalChunksFor1MB;

    /* ── 2. AES-256-GCM only ── */
    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const aesT0 = performance.now();
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, payload);
    const aesMs = performance.now() - aesT0;

    /* ── 3. Hybrid: RSA wraps fresh AES key, AES-GCM does bulk ── */
    const hybridT0 = performance.now();
    const freshAes = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const rawAesKey = await crypto.subtle.exportKey('raw', freshAes);
    // Wrap (encrypt) the 32-byte AES key under RSA-OAEP
    await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPair.publicKey, rawAesKey);
    // Bulk-encrypt the payload under the AES key
    const iv2 = new Uint8Array(12);
    crypto.getRandomValues(iv2);
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv2 }, freshAes, payload);
    const hybridMs = performance.now() - hybridT0;

    setText('hybrid-rsa-time',    formatMs(rsaProjectedMs));
    setText('hybrid-aes-time',    formatMs(aesMs));
    setText('hybrid-hybrid-time', formatMs(hybridMs));

    setText('hybrid-rsa-note',
      `~${Math.round(totalChunksFor1MB).toLocaleString()} RSA ops · sampled ${sampleChunks} chunks at ${(rsaSampleMs / sampleChunks).toFixed(2)} ms each`,
    );
    setText('hybrid-aes-note',    'one AES-GCM call, no asymmetric work');
    setText('hybrid-hybrid-note', '1 RSA wrap + 1 AES-GCM bulk = constant asymmetric cost');

    const speedup = rsaProjectedMs / Math.max(0.001, hybridMs);
    const aesSpeedup = rsaProjectedMs / Math.max(0.001, aesMs);
    const takeawayEl = document.getElementById('hybrid-takeaway-text') as HTMLElement;
    takeawayEl.textContent =
      `RSA-only would take ~${formatMs(rsaProjectedMs)} ms to encrypt 1 MB — about ${speedup.toFixed(0)}× slower than the hybrid scheme ` +
      `(${formatMs(hybridMs)} ms) and ${aesSpeedup.toFixed(0)}× slower than pure AES (${formatMs(aesMs)} ms). ` +
      `TLS, S/MIME, age, and JWE all use the hybrid pattern for exactly this reason: RSA is for key transport, AES is for bulk data.`;

    show('hybrid-results');
    show('hybrid-takeaway');
    announce(`Hybrid timing complete. RSA-only projected ${formatMs(rsaProjectedMs)} ms, AES-only ${formatMs(aesMs)} ms, hybrid ${formatMs(hybridMs)} ms.`);
  } catch (err: unknown) {
    announce(`Hybrid timing failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    setLoading(btn, false, lbl);
  }
}

function formatMs(ms: number): string {
  if (ms >= 10_000) return Math.round(ms).toLocaleString();
  if (ms >= 100)    return Math.round(ms).toString();
  return ms.toFixed(1);
}
