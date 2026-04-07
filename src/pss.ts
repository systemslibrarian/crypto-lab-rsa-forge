/**
 * pss.ts — RSA-PSS via WebCrypto API (Panel 3).
 *
 * Signs with RSA-PSS-SHA-256, sLen = 32 (salt length = hash length).
 * Verifies against correct and tampered messages.
 * Specified in RFC 8017 (PKCS#1 v2.2) §8.1, §9.1.
 */

import { announce, show, setText, setLoading, toBase64 } from './ui.js';

interface PssKeyPair {
  publicKey:  CryptoKey;
  privateKey: CryptoKey;
}

let pssKey: PssKeyPair | null = null;
let pssSignature: ArrayBuffer | null = null;
let pssOriginalMessage = '';

export function initPssPanel(): void {
  (document.getElementById('pss-gen') as HTMLButtonElement)
    .addEventListener('click', generateKey);
  (document.getElementById('pss-sign') as HTMLButtonElement)
    .addEventListener('click', signMessage);
  (document.getElementById('pss-verify-ok') as HTMLButtonElement)
    .addEventListener('click', () => verifyMessage(false));
  (document.getElementById('pss-verify-tampered') as HTMLButtonElement)
    .addEventListener('click', () => verifyMessage(true));
}

/* ── Key Generation ─────────────────────────────────────────── */
async function generateKey(): Promise<void> {
  const btn = document.getElementById('pss-gen') as HTMLButtonElement;
  const lbl = btn.getAttribute('aria-label') ?? 'Generate signing key';
  setLoading(btn, true);
  announce('Generating RSA-PSS 2048-bit signing key via WebCrypto…');

  try {
    const pair = await crypto.subtle.generateKey(
      {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      false,
      ['sign', 'verify'],
    ) as CryptoKeyPair;

    pssKey = { publicKey: pair.publicKey, privateKey: pair.privateKey };

    const statusEl = document.getElementById('pss-keygen-status');
    if (statusEl) statusEl.textContent = '2048-bit RSA-PSS key pair ready.';

    show('pss-sign-section');
    announce('RSA-PSS 2048-bit signing key generated.');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    announce(`Key generation failed: ${msg}`);
  } finally {
    setLoading(btn, false, lbl);
  }
}

/* ── Sign ───────────────────────────────────────────────────── */
async function signMessage(): Promise<void> {
  if (!pssKey) { announce('Generate a signing key first.'); return; }

  const msgEl = document.getElementById('pss-message') as HTMLTextAreaElement;
  const msg = msgEl.value;
  if (!msg.trim()) {
    announce('Enter a message to sign.');
    msgEl.focus();
    return;
  }

  const btn = document.getElementById('pss-sign') as HTMLButtonElement;
  const lbl = btn.getAttribute('aria-label') ?? 'Sign message';
  setLoading(btn, true);
  announce('Signing message with RSA-PSS-SHA-256…');

  try {
    const msgBytes = new TextEncoder().encode(msg);
    const sig = await crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32, // sLen = hLen for SHA-256 (RFC 8017 §9.1 recommends sLen = hLen)
      },
      pssKey.privateKey,
      msgBytes,
    );

    pssSignature      = sig;
    pssOriginalMessage = msg;

    const b64 = toBase64(new Uint8Array(sig));
    setText('pss-signature', b64);
    show('pss-signature-result');
    show('pss-verify-card');
    announce(`Message signed. Signature is ${sig.byteLength} bytes.`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    announce(`Signing failed: ${msg}`);
  } finally {
    setLoading(btn, false, lbl);
  }
}

/* ── Verify ─────────────────────────────────────────────────── */
async function verifyMessage(tamper: boolean): Promise<void> {
  if (!pssKey || !pssSignature) { announce('Sign a message first.'); return; }

  const btnId = tamper ? 'pss-verify-tampered' : 'pss-verify-ok';
  const btn = document.getElementById(btnId) as HTMLButtonElement;
  const lbl = btn.getAttribute('aria-label') ?? '';
  setLoading(btn, true);

  const verifyMsg = tamper
    ? pssOriginalMessage + ' (tampered)'
    : pssOriginalMessage;

  announce(`Verifying signature against ${tamper ? 'tampered' : 'original'} message…`);

  try {
    const msgBytes = new TextEncoder().encode(verifyMsg);
    const valid = await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      pssKey.publicKey,
      pssSignature,
      msgBytes,
    );

    const iconEl   = document.getElementById('pss-verify-icon')   as HTMLElement;
    const statusEl = document.getElementById('pss-verify-status') as HTMLElement;
    const textEl   = document.getElementById('pss-verify-text')   as HTMLElement;
    const outputEl = document.getElementById('pss-verify-output') as HTMLElement;

    if (valid) {
      outputEl.className = 'result-box result-box-success';
      iconEl.textContent   = '✓';
      statusEl.textContent = 'Signature valid';
      textEl.textContent   = `Message verified: "${verifyMsg}"`;
      announce('Signature is valid. The message is authentic and unmodified.');
    } else {
      outputEl.className = 'result-box result-box-error';
      iconEl.textContent   = '✗';
      statusEl.textContent = 'Signature invalid';
      textEl.textContent   = tamper
        ? `Signature rejected for tampered message: "${verifyMsg}". PSS correctly detected modification.`
        : 'Unexpected: signature rejected for original message.';
      announce(
        tamper
          ? 'Signature correctly rejected — tampered message detected.'
          : 'Signature rejected for original message (unexpected).',
      );
    }
    show('pss-verify-output');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    announce(`Verification error: ${msg}`);
  } finally {
    setLoading(btn, false, lbl);
  }
}
