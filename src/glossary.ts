/**
 * glossary.ts — Just-in-time inline definitions.
 *
 * Any element with class="gloss" and data-gloss="<key>" becomes a dotted-underline
 * term. Hover, keyboard focus, or tap/click reveals a shared single popover with a
 * plain-language definition — no new UI per term, WCAG-friendly (role=button,
 * aria-expanded, Escape to close, accessible via keyboard).
 *
 * Definitions serve both audiences: a beginner gets the intuition, and each
 * closes with the precise term/property so a professional still gets signal.
 */

interface GlossEntry { term: string; def: string; }

const GLOSSARY: Record<string, GlossEntry> = {
  trapdoor: {
    term: 'Trapdoor (one-way) function',
    def: 'A computation that is easy to run forwards but effectively impossible to reverse — unless you hold a secret. RSA’s trapdoor is multiplication: multiplying two big primes into n is instant, but factoring n back into those primes is infeasible without knowing them.',
  },
  phi: {
    term: 'φ(n) — Euler’s totient',
    def: 'The count of integers from 1 to n that share no common factor with n. For n = p·q it equals (p−1)(q−1). It is the “clock size” that decides which exponent d undoes e; you can only compute it if you know the secret primes p and q.',
  },
  modexp: {
    term: 'Modular exponentiation',
    def: 'Raising a number to a power and taking the remainder mod n, e.g. m^e mod n. Cheap to compute forwards, but recovering m from the result (the RSA problem) is believed as hard as factoring n. It is the core operation of both encrypting and decrypting.',
  },
  mgf1: {
    term: 'MGF1 — Mask Generation Function 1',
    def: 'A way to stretch a short seed into an arbitrarily long pseudorandom “mask” by hashing seed‖counter repeatedly (RFC 8017 §B.2.1). OAEP and PSS XOR data with such masks so that flipping any input bit scrambles the whole block.',
  },
  crt: {
    term: 'CRT — Chinese Remainder Theorem',
    def: 'Given a number’s remainders modulo several pairwise-coprime moduli, CRT reconstructs the unique value modulo their product. In the Håstad attack it stitches three ciphertexts c_i = m³ mod n_i back into the exact integer m³.',
  },
  semantic: {
    term: 'Semantic security',
    def: 'A ciphertext leaks nothing computable about the plaintext — not even whether two ciphertexts encrypt the same message. Randomized padding (OAEP) provides it; deterministic textbook RSA does not.',
  },
  indcca2: {
    term: 'IND-CCA2',
    def: 'Indistinguishability under adaptive chosen-ciphertext attack: the strongest standard notion of encryption security. Even an attacker who can get chosen ciphertexts decrypted learns nothing about a target ciphertext. RSA-OAEP targets this; PKCS#1 v1.5 encryption famously does not (see the Bleichenbacher panel).',
  },
  homomorphic: {
    term: 'Homomorphic property',
    def: 'When an operation on ciphertexts mirrors an operation on the plaintexts inside them. Raw RSA is multiplicatively homomorphic: Enc(a)·Enc(b) mod n = Enc(a·b). Useful in theory, but it is exactly the lever that malleability and padding-oracle attacks exploit.',
  },
  avalanche: {
    term: 'Avalanche effect',
    def: 'A tiny change to the input (one flipped bit) changes about half of all output bits. It is why OAEP’s scrambled block looks totally different when the message or random seed changes by even one byte.',
  },
  oaep: {
    term: 'OAEP — Optimal Asymmetric Encryption Padding',
    def: 'The padding you wrap around a message before RSA encryption (RFC 8017 §7.1). It mixes in a random seed so encryption is randomized and non-malleable, upgrading raw RSA to semantic / IND-CCA2 security.',
  },
  pss: {
    term: 'PSS — Probabilistic Signature Scheme',
    def: 'The padding used for RSA signatures (RFC 8017 §8.1). A fresh random salt per signature gives a tight security proof reducing forgery to inverting RSA — the reason PSS is preferred over deterministic PKCS#1 v1.5 signatures.',
  },
};

export function initGlossary(): void {
  const pop     = document.getElementById('gloss-body')          as HTMLElement | null;
  const termEl  = document.getElementById('gloss-popover-term')  as HTMLElement | null;
  const defEl   = document.getElementById('gloss-popover-def')   as HTMLElement | null;
  if (!pop || !termEl || !defEl) return;

  const terms = Array.from(document.querySelectorAll<HTMLElement>('.gloss[data-gloss]'));
  let current: HTMLElement | null = null;  // term the popover is currently showing
  let pinned: HTMLElement | null = null;   // term explicitly opened by click/keyboard

  const hidePop = () => {
    pop.hidden = true;
    if (current) current.setAttribute('aria-expanded', 'false');
    current = null;
    pinned = null;
  };

  const showFor = (el: HTMLElement) => {
    const key = el.dataset.gloss ?? '';
    const entry = GLOSSARY[key];
    if (!entry) return;
    termEl.textContent = entry.term;
    defEl.textContent  = entry.def;

    // Position the popover under the term, clamped to the viewport.
    pop.hidden = false;
    const r = el.getBoundingClientRect();
    const margin = 8;
    const popW = Math.min(pop.offsetWidth || 320, window.innerWidth - 2 * margin);
    let left = r.left + window.scrollX;
    left = Math.max(margin, Math.min(left, window.scrollX + window.innerWidth - popW - margin));
    pop.style.left = `${left}px`;
    pop.style.top  = `${r.bottom + window.scrollY + 6}px`;

    if (current && current !== el) current.setAttribute('aria-expanded', 'false');
    el.setAttribute('aria-expanded', 'true');
    current = el;
  };

  // Click / keyboard toggles a persistent "pin"; independent of hover state so a
  // hover-then-click never double-toggles the popover shut.
  const togglePin = (el: HTMLElement) => {
    if (pinned === el) { hidePop(); }
    else { showFor(el); pinned = el; }
  };

  terms.forEach((el) => {
    // Hover (mouse) — quick preview; never disturbs a pinned popover.
    el.addEventListener('mouseenter', () => { if (!pinned) showFor(el); });
    el.addEventListener('mouseleave', () => {
      if (!pinned && current === el && document.activeElement !== el) hidePop();
    });
    // Keyboard focus — reveal for tab users (unless something is pinned).
    el.addEventListener('focus', () => { if (!pinned) showFor(el); });
    el.addEventListener('blur',  () => { if (!pinned && current === el) hidePop(); });
    // Click / tap — toggle pin (essential for touch, which has no hover).
    el.addEventListener('click', (e) => { e.preventDefault(); togglePin(el); });
    el.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); togglePin(el); }
      else if (e.key === 'Escape') { hidePop(); el.blur(); }
    });
  });

  // Dismiss on outside click or Escape anywhere.
  document.addEventListener('click', (e) => {
    const t = e.target as HTMLElement;
    if (!pop.hidden && !pop.contains(t) && !t.classList.contains('gloss')) hidePop();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hidePop(); });
  window.addEventListener('resize', hidePop);
}
