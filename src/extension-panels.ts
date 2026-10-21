/** Appended panels only; the original tab IDs and navigation stay intact. */
export function mountExtensionPanels(): void {
  const tabs = document.querySelector('.tab-list')!;
  for (const [id,title] of [[7,'Implementation Pitfalls'],[8,'Parity Oracle']]) tabs.insertAdjacentHTML('beforeend',`<li role="none"><button class="tab-btn" role="tab" id="tab-${id}" aria-selected="false" aria-controls="panel-${id}" data-panel="${id}" tabindex="-1"><span class="tab-status-dot tab-status-danger" aria-hidden="true"></span><span>${title}</span></button></li>`);
  document.getElementById('main-content')!.insertAdjacentHTML('beforeend',`
<section id="panel-7" class="panel rsa-extension" role="tabpanel" aria-labelledby="tab-7" tabindex="0" hidden>
 <div class="panel-header"><h2 class="panel-title">Implementation Pitfalls</h2><p class="panel-description">RSA can be mathematically sound and still lose its private key through a deployment mistake. Flip one bit in a signing calculation, or give two employees the same modulus, and watch arithmetic expose the secret.</p></div>
 <div class="card"><h3 class="card-title">1. One faulty signature factors N</h3><p>The signer computes two halves and joins them. One wrong half leaves a result that still agrees modulo the other prime. Taking a greatest common divisor isolates that prime. The bit flip is simulated in this lab's BigInt signer; WebCrypto itself is never faulted.</p>
  <div class="btn-group"><button class="btn btn-primary" id="fault-generate">Generate RSA-2048 key</button><button class="btn btn-secondary" id="fault-sign" disabled>Sign correctly</button></div>
  <label for="fault-message">Message to sign</label><input class="form-input" id="fault-message" value="Approve this teaching example." maxlength="160">
  <label for="fault-bit">Bit of the q half to flip (0–1023)</label><input class="form-input" id="fault-bit" type="number" min="0" max="1023" value="0">
  <label class="extension-toggle"><input id="fault-protect" type="checkbox" checked> Verify before release (recommended)</label>
  <p id="fault-mode">Countermeasure ON: withhold any signature that fails verification.</p>
  <div class="btn-group"><button class="btn btn-danger" id="fault-inject" disabled>Inject fault</button><button class="btn btn-danger" id="fault-factor" disabled>Factor from released signature</button></div>
  <p id="fault-status" role="status" aria-live="polite">Generate a fresh key to begin.</p>
  <div id="fault-result" role="status" aria-live="polite"></div>
  <details><summary>Inspect the CRT values and local teaching key</summary><p>Fresh local teaching values; not stored or sent anywhere. A withheld signature is visible here for study, but the attacker function cannot receive it.</p><div id="fault-values"></div></details>
  <p class="citation">Single-fault route: Joye, Lenstra &amp; Quisquater (1999), <a href="https://link.springer.com/article/10.1007/s001459900055">Chinese Remaindering Based Cryptosystems in the Presence of Faults</a>. Correct-plus-faulty route: Boneh, DeMillo &amp; Lipton, EUROCRYPT 1997.</p>
 </div>
 <div class="card"><h3 class="card-title">2. Shared modulus I: an insider exposes every colleague</h3><p>Different public and private exponents do not isolate employees who share N. A's valid key pair gives e<sub>A</sub>d<sub>A</sub> − 1, a multiple of λ(N) = lcm(p − 1, q − 1). Repeated squaring can then expose a non-trivial square root of 1 and factor the shared modulus.</p>
  <p class="citation">This fixture chooses d modulo φ(N), but the attack also works when d is an inverse only modulo λ(N), as required by <a href="https://www.rfc-editor.org/rfc/rfc8017.html#section-3.2">RFC 8017 §3.2</a>. λ(N) is the exponent of the multiplicative group; its order is φ(N) = (p − 1)(q − 1).</p>
  <div class="btn-group"><button class="btn btn-primary" id="shared-issue">Issue two employee key pairs</button><button class="btn btn-danger" id="shared-factor" disabled>Factor from A's pair</button><button class="btn btn-danger" id="shared-read" disabled>Read B's message</button></div>
  <p id="shared-status" role="status" aria-live="polite">Fresh 512-bit teaching modulus; never use this size in production.</p><div id="shared-checks"></div><div id="shared-result" role="status" aria-live="polite"></div>
  <details><summary>Inspect employee keys and retry arithmetic</summary><div id="shared-values"></div></details>
  <p class="citation">Katz–Lindell §12.5.6, Corollary 9.51; DeLaurentis (1984). The randomized loop counts unsuccessful bases and refuses honestly if its retry budget is exhausted.</p>
 </div>
 <div class="card"><h3 class="card-title">3. Shared modulus II: two public encryptions reveal one message</h3><p>An outsider combines two ciphertexts of the same raw message under coprime exponents. The exponents' integer combination is one, so the powers combine back into the message.</p>
  <label for="common-message">Message to both recipients</label><input class="form-input" id="common-message" value="Same memo" maxlength="64">
  <div class="btn-group"><button class="btn btn-primary" id="common-encrypt">Encrypt same message twice</button><button class="btn btn-danger" id="common-attack" disabled>Attack with public values</button><button class="btn btn-secondary" id="common-oaep" disabled>Try fresh OAEP encodings</button></div>
  <p id="common-status" role="status" aria-live="polite">Generate a fresh RSA-2048 example.</p><div id="common-result" role="status" aria-live="polite"></div>
  <details><summary>Inspect public ciphertexts and Bézout coefficients</summary><div id="common-values"></div></details>
  <p>OAEP encodes the same message differently each time. This contrast does not repair shared keys against an insider. Reusing the same OAEP-encoded integer makes the public attack work again.</p>
  <p class="citation">Simmons (1983), common-modulus attack; <a href="https://crypto.stanford.edu/~dabo/pubs/abstracts/RSAattack-survey.html">Boneh's RSA attack survey (1999)</a>.</p>
 </div>
 <p>Not shown: faults against randomized RSA-PSS; physical fault injection; Manger-style OAEP oracles; <a href="https://systemslibrarian.github.io/crypto-lab-rsa-small-roots/">partial-key and lattice attacks</a>; <a href="https://systemslibrarian.github.io/crypto-lab-factor-forge/">batch GCD across many moduli</a>. This is a teaching demo, not production crypto.</p>
</section>
<section id="panel-8" class="panel rsa-extension" role="tabpanel" aria-labelledby="tab-8" tabindex="0" hidden>
 <div class="panel-header"><h2 class="panel-title">Parity Oracle — one bit is enough</h2><p class="panel-description">This deliberately BROKEN server decrypts a ciphertext but returns only whether the result is odd. Ask about carefully related ciphertexts, and that one-bit answer reveals the original message from its low bits upward. The attack receives no private key.</p></div>
 <div class="card"><h3 class="card-title">Recover the low bits, one query at a time</h3>
  <label for="parity-size">Modulus size</label><select class="form-input" id="parity-size"><option value="512">512-bit teaching size (fast)</option><option value="2048">2048-bit WebCrypto key (CRT server)</option></select>
  <label for="parity-message">Message hidden behind the oracle</label><input class="form-input" id="parity-message" maxlength="48" value="One bit is enough.">
  <div class="btn-group"><button class="btn btn-primary" id="parity-setup">Setup fresh server</button><button class="btn btn-secondary" id="parity-step" disabled>Step one query</button><button class="btn btn-danger" id="parity-run" disabled>Run to end</button><button class="btn btn-secondary" id="parity-cancel" disabled>Cancel</button></div>
  <p>Try the first 16 queries by hand, then run to the end. The first query uses the original ciphertext. Before each later query, multiply the current ciphertext by 2<sup>−e</sup> modulo N. The returned bits determine the message's low bits; no factorization is used.</p>
  <p id="parity-status" role="status" aria-live="polite">Setup a fresh server to begin.</p>
  <p>Queries: <output id="parity-count">0</output> / <span id="parity-total">0</span>. Known low bits: <span id="parity-known-count">0</span>.</p>
  <div class="byte-reveal-container"><p class="byte-reveal-label">Plaintext bytes fill from right to left</p><div id="parity-byte-row" class="byte-row" role="group" aria-label="Recovered byte grid"></div></div>
  <div id="parity-result" role="status" aria-live="polite"></div>
  <details><summary>Inspect the public values and one-bit oracle log</summary><div id="parity-values"></div><p>Only oracle responses (0 or 1):</p><pre id="parity-bits" tabindex="0" role="region" aria-label="One-bit oracle responses"></pre><p id="parity-formula"></p></details>
 </div>
 <p>The server leaks a bit of the raw RSA preimage for every ciphertext. Whether a padded deployment leaks this bit depends on where its decryption leaks. Compare the <a href="#tab-5" id="parity-related">Bleichenbacher oracle tab</a>; this panel makes no claim that OAEP or PSS leaks parity.</p>
 <p class="citation">Katz–Lindell §12.5.3, Theorem 12.31 (halving recovery); Alexi, Chor, Goldreich &amp; Schnorr, SIAM Journal on Computing 17 (1988), 194–209. All cryptographic operations and checks are real; this deliberately vulnerable server is only a local teaching example.</p>
</section>`);
}
