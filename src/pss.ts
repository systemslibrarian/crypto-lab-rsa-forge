/**
 * pss.ts — RSA-PSS via WebCrypto API (Panel 3).
 *
 * Signs with RSA-PSS-SHA-256, sLen = 32 (salt length = hash length).
 * Verifies against correct and tampered messages.
 * Specified in RFC 8017 (PKCS#1 v2.2) §8.1, §9.1.
 */

import { announce, show, setText, setLoading, toBase64, toHex } from './ui.js';
import { pssEncode, type PssFields } from './pss-encode.js';

interface PssKeyPair {
  publicKey:  CryptoKey;
  privateKey: CryptoKey;
}

let pssKey: PssKeyPair | null = null;
let pssSignature: ArrayBuffer | null = null;
let pssOriginalMessage = '';
let lastPssFields: PssFields | null = null;

export function initPssPanel(): void {
  (document.getElementById('pss-gen') as HTMLButtonElement)
    .addEventListener('click', generateKey);
  (document.getElementById('pss-sign') as HTMLButtonElement)
    .addEventListener('click', signMessage);
  (document.getElementById('pss-verify-ok') as HTMLButtonElement)
    .addEventListener('click', () => verifyMessage(false));
  (document.getElementById('pss-verify-tampered') as HTMLButtonElement)
    .addEventListener('click', () => verifyMessage(true));

  initPssDiagramHover();
}

/* ── Diagram hover with real bytes ─────────────────────────── */
const PSS_FIELD_LABELS: Record<string, string> = {
  zeros8:    '8 leading zero bytes (RFC 8017 §9.1.1 step 4)',
  mHash:     'mHash = SHA-256(your message)',
  salt:      'salt — sLen random bytes (fresh each signature)',
  H:         'H = SHA-256(0×8 ‖ mHash ‖ salt)',
  ps:        'PS — zero padding string in DB',
  separator: '0x01 separator byte in DB',
  saltDB:    'salt copy used inside DB',
  maskedDB:  'maskedDB = DB XOR MGF1(H, emLen−hLen−1)',
  H2:        'H — same digest, embedded in EM',
  trailer:   '0xBC trailer byte (RFC 8017 §9.1.1 step 12)',
};

function pssFieldBytes(f: PssFields, name: string): Uint8Array | null {
  switch (name) {
    case 'zeros8':    return f.zeros8;
    case 'mHash':     return f.mHash;
    case 'salt':      return f.salt;
    case 'H':         return f.H;
    case 'ps':        return f.ps;
    case 'separator': return f.separator;
    case 'saltDB':    return f.saltDB;
    case 'maskedDB':  return f.maskedDB;
    case 'H2':        return f.H;
    case 'trailer':   return f.trailer;
    default:          return null;
  }
}

function pssFormatHex(bytes: Uint8Array, max = 64): string {
  if (bytes.length === 0) return '(empty)';
  const shown = bytes.subarray(0, max);
  const groups: string[] = [];
  for (let i = 0; i < shown.length; i += 4) {
    groups.push(toHex(shown.subarray(i, i + 4)));
  }
  let out = groups.join(' ');
  if (bytes.length > max) out += `  …(+${bytes.length - max} more bytes)`;
  return out;
}

function initPssDiagramHover(): void {
  const tooltip = document.getElementById('pss-tooltip') as HTMLElement | null;
  if (!tooltip) return;
  const labelEl = document.getElementById('pss-tooltip-label') as HTMLElement;
  const bytesEl = document.getElementById('pss-tooltip-bytes') as HTMLElement;
  const segments = document.querySelectorAll<HTMLElement>('[data-pss-field]');

  const positionTooltip = (target: HTMLElement) => {
    const parent = tooltip.parentElement!;
    const parentRect = parent.getBoundingClientRect();
    const targetRect = target.getBoundingClientRect();
    const left = targetRect.left - parentRect.left;
    const top  = targetRect.bottom - parentRect.top + 6;
    tooltip.style.left = `${Math.max(8, Math.min(left, parent.clientWidth - 360))}px`;
    tooltip.style.top  = `${top}px`;
  };

  const showTip = (target: HTMLElement) => {
    const field = target.dataset.pssField!;
    labelEl.textContent = PSS_FIELD_LABELS[field] ?? field;
    if (!lastPssFields) {
      bytesEl.innerHTML = '<span class="diagram-tooltip-empty">Sign a message above to see real bytes here.</span>';
    } else {
      const bytes = pssFieldBytes(lastPssFields, field);
      if (!bytes) {
        bytesEl.textContent = '(no data)';
      } else {
        bytesEl.textContent = `${bytes.length} bytes:  ${pssFormatHex(bytes)}`;
      }
    }
    positionTooltip(target);
    tooltip.classList.add('visible');
  };

  const hideTip = () => tooltip.classList.remove('visible');

  segments.forEach(seg => {
    seg.addEventListener('mouseenter', () => showTip(seg));
    seg.addEventListener('mouseleave', hideTip);
    seg.addEventListener('focus',      () => showTip(seg));
    seg.addEventListener('blur',       hideTip);
    seg.tabIndex = 0;
  });
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

    // Compute PSS-encoded intermediate fields (independent random salt)
    // so the diagram hover can show real bytes for this message.
    try { lastPssFields = await pssEncode(msgBytes); } catch { lastPssFields = null; }

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
