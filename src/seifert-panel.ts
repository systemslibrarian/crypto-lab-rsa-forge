/**
 * Panel 9 — Fault the verifier (Seifert's attack).
 *
 * Two cards: a toy run that faults a real small key's modulus and forges a
 * signature the faulted verifier accepts; and the real 2048-bit Xbox modulus,
 * with the two facts from Muir §4.3 recomputed in the browser.
 */
import {
  XBOX_MODULUS,
  XBOX_MODULUS_HEX,
  runToyAttack,
  seifertSuccessProbability,
  verify,
  xboxByte16Factorization,
  xboxSmallestPrimeByte,
  type ToyRun,
} from './seifert.js';
import { chip, escape, showValues } from './pitfalls-panel.js';

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const hex = (n: bigint): string => n.toString(16);
const short = (n: bigint, head = 12, tail = 8): string => {
  const h = hex(n);
  return h.length <= head + tail + 1 ? h : `${h.slice(0, head)}…${h.slice(-tail)}`;
};

export function initSeifertPanel(): void {
  initToy();
  initXbox();
}

function initToy(): void {
  const message = el<HTMLInputElement>('seifert-message');
  let busy = false;
  let revision = 0;
  let oldMessage = message.value;

  function retire(): void {
    revision++;
    busy = false;
    el('seifert-result').replaceChildren();
    showValues('seifert', {});
    el('seifert-status').textContent = 'Previous run retired. Forge under the current message.';
    el<HTMLButtonElement>('seifert-forge').disabled = false;
  }
  message.addEventListener('input', () => {
    if (message.value !== oldMessage) {
      oldMessage = message.value;
      retire();
    }
  });

  el('seifert-forge').addEventListener('click', async () => {
    if (busy) return;
    const token = ++revision;
    busy = true;
    el<HTMLButtonElement>('seifert-forge').disabled = true;
    el('seifert-result').replaceChildren();
    el('seifert-status').textContent = 'Generating a real 512-bit key, then faulting its modulus…';
    try {
      if (!message.value.trim()) throw new Error('Enter a nonempty message to forge a signature on.');
      await new Promise((r) => setTimeout(r, 0));
      const run = await runToyAttack(message.value, 512);
      if (token !== revision) return;
      if ('error' in run) throw new Error('No forgeable fault found in the scanned bytes; regenerate.');
      render(run);
    } catch (error) {
      if (token === revision) el('seifert-status').textContent = error instanceof Error ? error.message : String(error);
    } finally {
      if (token === revision) {
        busy = false;
        el<HTMLButtonElement>('seifert-forge').disabled = false;
      }
    }
  });

  function render(run: ToyRun): void {
    const a = run.search.analysis;
    const route =
      a.route === 'prime'
        ? 'N̂ came out prime, so φ(N̂) = N̂ − 1'
        : `N̂ split into ${a.factors!.length} small primes, so φ(N̂) = Π(pᵢ − 1)`;
    // Independent re-check, in the panel: s^e mod N̂ must equal h, and must not mod N.
    const faulted = verify(run.forgedSignature, run.h, run.e, run.search.nHat);
    const honest = verify(run.forgedSignature, (run.h % run.N) as bigint, run.e, run.N);
    el('seifert-result').innerHTML =
      `<p id="seifert-fault-line">Faulted byte ${run.search.byteIndex} of N from 0x${run.search.originalByte
        .toString(16)
        .padStart(2, '0')} to 0x${run.search.faultedByte.toString(16).padStart(2, '0')}; ${escape(route)}.</p>` +
      `<p>The attacker computed d̂ = e⁻¹ mod φ(N̂) and signed the message — no factoring of the real N, no private key.</p>` +
      `<p id="seifert-faulted-check" data-state="${faulted ? 'pass' : 'fail'}">${
        faulted ? '✓' : '✗'
      } The faulted verifier (checks against N̂) ${faulted ? 'ACCEPTS' : 'rejects'} the forged signature.</p>` +
      `<p id="seifert-honest-check" data-state="${honest ? 'fail' : 'pass'}">${
        honest ? '✗' : '✓'
      } An honest verifier (checks against the real N) ${honest ? 'accepts' : 'REJECTS'} it.</p>` +
      chip(
        faulted && !honest ? 'danger' : 'warn',
        faulted && !honest ? 'FORGED — a one-byte fault in the verifier accepted an attacker signature' : 'Run did not demonstrate the split',
      );
    showValues('seifert', {
      N: run.N,
      e: run.e,
      Nhat: run.search.nHat,
      h: run.h,
      dhat: a.dHat,
      sig: run.forgedSignature,
    });
    el('seifert-status').textContent =
      faulted && !honest
        ? 'Forged: the faulted modulus accepted a signature the real key never produced.'
        : 'Run complete.';
  }
}

function initXbox(): void {
  el('seifert-xbox-run').addEventListener('click', () => {
    el<HTMLButtonElement>('seifert-xbox-run').disabled = true;
    el('seifert-xbox-status').textContent = 'Scanning the real 2048-bit modulus…';
    // Defer so the status paints before the (fast) scans.
    setTimeout(() => {
      const prime = xboxSmallestPrimeByte();
      const b16 = xboxByte16Factorization();
      el('seifert-xbox-result').innerHTML =
        `<p id="seifert-xbox-prime" data-byte="${prime.smallestPrimeByte}">Smallest byte whose zeroing makes the modulus prime: <strong>byte ${prime.smallestPrimeByte}</strong>. Muir §4.3 states j = 104.</p>` +
        `<p id="seifert-xbox-b16" data-match="${b16.productMatches && b16.cofactorIsPrime}">Zeroing byte 16 gives <code>3 · 13 · 199 · 856469 · p₀</code>, with p₀ a ${b16.cofactorBits}-bit ${
          b16.cofactorIsPrime ? 'prime' : 'composite'
        } (p₀ = 0x${short(b16.cofactor)}). The four small primes times p₀ ${
          b16.productMatches ? 'equal' : 'do not equal'
        } the faulted modulus.</p>` +
        chip(
          prime.smallestPrimeByte === 104 && b16.productMatches && b16.cofactorIsPrime ? 'danger' : 'warn',
          prime.smallestPrimeByte === 104 && b16.productMatches && b16.cofactorIsPrime
            ? "Both of Muir's §4.3 facts reproduce on the real modulus"
            : 'Facts did not reproduce',
        );
      el('seifert-xbox-status').textContent = 'Done — both facts recomputed from the printed modulus.';
    }, 0);
  });
}

/** The §3.1 success-probability note, rendered once at mount. */
export function seifertProbabilityRows(): string {
  // 1 − (1 − 0.00282)^(2^b − 1), the §3.1 formula (RSA-1024, e = 65537).
  return [4, 6, 8]
    .map((b) => `<tr><td>${b}</td><td>${(seifertSuccessProbability(b) * 100).toFixed(1)}%</td></tr>`)
    .join('');
}

/** The Xbox modulus, grouped for display. Exposed for the panel markup. */
export const XBOX_DISPLAY = XBOX_MODULUS_HEX.replace(/(.{64})/g, '$1\n');
export { XBOX_MODULUS };
