# Extension brief — `crypto-lab-rsa-forge`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-rsa-forge` at `925498c1f145` and `audits/_MASTER-TEMPLATE.md` (catalog
`f48d9d2f2f06`). Template §5: "Extend, never restructure." Source of the gap: Katz–Lindell,
*Introduction to Modern Cryptography*, 3rd ed. (CRC Press, 2021), §12.5.6 "RSA Implementation
Issues and Pitfalls" and §12.5.3 (the RSA hard-core bit, Theorem 12.31).

**Verdict: extension — two new tabs (`tab-7`, `tab-8`) inside the existing lab.**

## What the lab has now (read at `925498c1f145`)

- Six tabs, `index.html:226–265`: Textbook RSA, RSA-OAEP, RSA-PSS, Small Exponent Attack
  (Håstad), Bleichenbacher Oracle, RSA vs ECC vs PQ. A separate `#oracle-without-factoring`
  paper brief (√eNFS, ePrint 2026/2131) sits at `index.html:1584`.
- `src/textbook.ts` — BigInt helpers this extension reuses rather than re-writes: `modPow` (:20),
  `millerRabin` (:38), `generatePrime` (:107), `extGcd` (:115), `modInverse` (:140), `gcd` (:147),
  `isqrt` (:160), `generateRsaKeyPair(totalBits, e)` (:212, returns `p, q, n, phi, e, d`).
- `src/attacks.ts` — `intCubeRoot` (:136), `crt3` (:159), the Håstad panel (:186–), PKCS#1 v1.5
  pad/unpad/oracle and `bleichenbacherAttack` (:447–515), `verify2026PaperForgery` (:45, checks
  the paper's published `s^65537 mod N = t`), `toyMultiplicativeRawOracle` (:61), the byte-reveal
  grid `initByteRevealGrid`/`updateByteReveal` (:1105, :1124), and `spkiModulus` (:318), which
  already exports a WebCrypto key as JWK.
- Tests: `test/attacks.test.ts`, `test/textbook.test.ts`, `test/oaep-pss.test.ts` (Vitest,
  `vitest.config.ts` includes `test/**/*.test.ts` only); `e2e/claims.spec.ts` (1,020 lines);
  `e2e/gate.ts` with `boot()` (:307) and `driveAllStates()` (:816); `e2e/a11y.spec.ts`.
  No `data-verdict` / `data-claim` markers and no mutation script exist in this repo.

Searched `src/*.ts`, `index.html` and `README.md` at this commit for `fault`, `common modulus`,
`shared modulus`, `parity`, `lsb`, `least significant`, `hard-core`, `Garner`: the only hits are
unrelated (`textbook.ts:101` "Set LSB (odd)", `index.html:1253` describing Lü et al.'s byte
order). None of the three attacks below exists here.

## What to add

**Tab 7 — Implementation Pitfalls (K-L §12.5.6).** Three cards, in the book's order.

1. **One faulty signature factors N.** Generate a real RSA-2048 key with WebCrypto
   (`RSASSA-PKCS1-v1_5`, SHA-256, `extractable: true`) and export it as JWK, which carries
   `p, q, dp, dq, qi`. Sign a message with WebCrypto to get the correct `s`; compute
   `EM = s^e mod N` (the deterministic PKCS#1 v1.5 encoding). Then run the lab's own BigInt CRT
   signer on the same `EM` — `s_p = EM^dp mod p`, `s_q = EM^dq mod q`, Garner recombination with
   `qi` — and let the learner flip one chosen bit of `s_q` before recombination. Show
   `gcd(s'^e − EM mod N, N) = p`, then `N / p = q`, and compare both to the JWK's `p`, `q`.
   Second route, shown beside it: `gcd(s − s', N)` with the correct signature. Countermeasure
   toggle: **verify before release** (`s'^e ≡ EM`), which withholds the faulty signature.
2. **Shared modulus I — any one key pair factors N (K-L Corollary 9.51).** One modulus, two
   "employees" with different `(e_A, d_A)`, `(e_B, d_B)` both inverse mod `φ(N)`. From
   `(N, e_A, d_A)` alone run the randomized algorithm: `k = e_A·d_A − 1 = 2^t·r`, random `g`,
   square `g^r` up to `t` times looking for a non-trivial square root of 1, output
   `gcd(x − 1, N)`. Then compute `d_B` and decrypt a message sent to B.
3. **Shared modulus II — the common-modulus attack (K-L §12.5.6, "Dependent public keys II").**
   The same textbook-RSA message to `(N, e1)` and `(N, e2)` with `gcd(e1, e2) = 1`: an
   eavesdropper with no key computes `X, Y` with `X·e1 + Y·e2 = 1` via `extGcd` and outputs
   `c1^X · c2^Y mod N` (a negative exponent uses `modInverse`). Contrast panel: the same message
   OAEP-encoded twice with the lab's own `oaepEncode` (`src/oaep-encode.ts:65`), raised to `e1`
   and `e2`; the attack outputs an integer that fails OAEP decoding, because the two encoded
   messages differ (K-L notes the attack still applies if the sender reuses one encoded message).

**Tab 8 — Parity Oracle (K-L §12.5.3).** A deliberately vulnerable "server" that decrypts any
ciphertext and reveals only `lsb(c^d mod N)`. Run the book's own recovery (pp. 443–444): given
`y = x^e`, query `y`, then repeatedly multiply by `2^{−e} mod N` and query again. After `i`
answers `b_0..b_{i−1}`, the low `i` bits of `x` are known exactly as
`(−N · Σ b_j 2^j) mod 2^i`, so the plaintext fills in **from the least significant byte up**
— reuse the byte-reveal grid from the Bleichenbacher tab, filling right to left. Total queries
equal `bitLength(N)` exactly. Default modulus 512 bits (sub-second); a "real size" run on a
WebCrypto RSA-2048 key with progress and Cancel (use `dp`/`dq` in the oracle so the 2,048
decryptions run at CRT speed).

**The headline mechanism** — Tab 7: a single wrong half of a CRT computation makes `s'^e − EM` a
multiple of exactly one prime. Tab 8: one bit per query, and the bits arrive as the plaintext's
own low-order bits. **Break-it-yourself:** the learner picks which bit of `s_q` to corrupt and
watches one `gcd` return a 1,024-bit prime of the real key; in Tab 8 the learner steps the first
16 queries by hand before letting it finish.

## Why two tabs, not one, and not inside Bleichenbacher

The three Tab 7 cards share the book's framing — a deployment mistake (an unchecked CRT result,
a modulus shared across users) breaks RSA with no oracle and no cryptanalysis — and §12.5.6
groups them under one heading, so they belong together. The parity oracle is a different kind
of thing: an adaptive chosen-ciphertext oracle attack, and the constructive side of a
provable-security result (Theorem 12.31: `lsb` is hard-core, so an oracle for it is as good as
a decryption key). Folding it into Tab 7 would blur "pitfalls" with "oracles". Folding it into
the Bleichenbacher tab would lengthen a panel whose step order the catalog's teaching worksheet
depends on (`crypto-lab/teach/_src/worksheets/public-key/rsa-forge.md` anchors on `#tab-4`,
`#tab-5` and IDs inside them). New tabs are appended; **no existing tab is renumbered.**

## SECURITY / CORRECTNESS INVARIANTS

1. Every recovered factor is checked by multiplication (`p·q = N`) and by `millerRabin` before
   the verdict renders; Tab 7 card 1 additionally compares against the JWK's `p`/`q`.
2. The fault is injected into the lab's own BigInt CRT signer only. WebCrypto's signer is never
   "faulted", and the page says the fault is simulated by a bit flip it chose.
3. The correct signature is accepted by `crypto.subtle.verify` before the attack runs; the
   faulty one is rejected by it. Both verdicts render from those calls.
4. Verify-before-release is ON by default. Turning it off is the visibly marked broken mode,
   never the arrival state.
5. The parity oracle is a separate closure holding the private key; the attack function's
   parameter list is `(N, e, y, oracle)` and nothing else, so "the attacker never sees `d`" is
   enforced by the signature rather than by a caption. Same for `commonModulusAttack`, which
   takes no private value at all.
6. The Tab 8 recovered plaintext is checked by re-encryption: `x^e mod N = y`.
7. No new code path changes the behaviour of tabs 1–6.

## ARCHITECTURE

- `src/pitfalls.ts` — `crtSign(EM, jwkParts, fault?)`, `factorFromFaultySignature`,
  `factorFromKeyPair(N, e, d)` (Corollary 9.51), `commonModulusAttack(N, e1, e2, c1, c2)`.
  Imports helpers from `textbook.ts`; adds no second `gcd`/`extGcd`.
- `src/parity.ts` — `makeParityOracle(N, d | {p,q,dp,dq,qi})`, `parityRecover(N, e, y, oracle,
  onStep)` (the book's halving variant).
- `src/jwk.ts` — base64url → bigint for `n, e, d, p, q, dp, dq, qi` (generalise the decoding
  already inlined in `spkiModulus`, `attacks.ts:318–325`; keep `spkiModulus` behaviour as is).
- UI wiring in a new `initPitfallsPanel()` / `initParityPanel()`, called from `src/main.ts`.
- `// [extension] point` in `pitfalls.ts` where a PSS fault card would go (see Non-goals).

## UI

- Tab 7: three `.card`s with the existing card styling. Card 1: Generate key → Sign correctly →
  choose bit index (number input, 0–1023, default random) → Inject fault → Factor. Shows
  `s`, `s'`, `s'^e − EM`, the gcd, and a side-by-side "= JWK p" check. Countermeasure toggle.
  Card 2: Issue two employee key pairs → Factor from A's pair → Read B's message. Card 3:
  Encrypt same message twice → Attack → OAEP contrast.
- Tab 8: Setup (512 / 2048) → "Step one query" (×16 by hand) → "Run to end" → Cancel. A query
  counter, the bit stream `b_0, b_1, …`, the right-to-left byte reveal, and the closing
  re-encryption check.
- Each card closes with a plain-language "what just happened" line, matching the existing
  attack panels.

## VISUAL SEMANTICS

A factor recovered from a faulty signature, a key derived from a colleague's key pair, and a
plaintext recovered by the parity oracle are **ALARM** states (the attack worked), not green.
"Faulty signature withheld" under the countermeasure is the integrity-preserved state. The
OAEP contrast's garbage output is shown as "attack failed — the two encoded messages differ".
Icon + text + colour everywhere; tab status dots for the new tabs use the existing
`tab-status-danger` class.

## EDGE CASES

- Bit index outside `0 … bitLength(q) − 1` → refused at the input with the valid range. (Any
  single flip inside that range changes `s_q` mod `q`, so the gcd is always `p`; the page can
  say why: the faulty result still agrees with the correct one mod `p`.)
- `gcd = 1` or `N` (only reachable through a defensive path, e.g. a future "fault both halves"
  option) → "no factor from this pair" with the cause; never a success verdict.
- Corollary 9.51 loop draws a `g` with no non-trivial root → retry, counted and shown (the book's
  algorithm succeeds with probability ≥ 1/2 per `g`).
- Common modulus with `gcd(e1, e2) ≠ 1` → refuse with the reason; `c2` not invertible mod `N` →
  `gcd(c2, N)` is a factor: report it as such.
- Parity run cancelled mid-way → shows the bits recovered so far as "partial", never as the
  plaintext.

## Tests

- **Vitest (`test/pitfalls.test.ts`, `test/parity.test.ts`):** fault attack recovers `p` on
  fresh keys (both fault halves); Corollary 9.51 factors 50 random keys; common-modulus recovers
  `m` and fails on the OAEP pair; parity recovery equals `x` on 512-bit keys and uses exactly
  `bitLength(N)` queries. **Independent route:** recover the same `x` with the
  interval-doubling variant (multiply by `2^e`, narrow `[0, N)`) written inside the test file,
  and assert equality with the halving variant.
- **`e2e/claims.spec.ts` additions:** parse `N` and the recovered `p` from the rendered verdict
  and assert `N mod p = 0` and `1 < p < N`; assert the rendered "= JWK p" check against the
  JWK exported in the test via `page.evaluate`; parse `X, Y, e1, e2` and assert
  `X·e1 + Y·e2 = 1`; parse the query counter and assert it equals the bit length of the
  rendered `N`; retirement (new key retires old verdicts); no-op guard.
- **Update** `e2e/claims.spec.ts:998–1010` ("each tab reveals exactly one panel"): it hard-codes
  `i <= 6`. Derive the count from `.tab-btn` and assert it is 8.
- **Extend `driveAllStates()`** (`e2e/gate.ts:816`) through both new tabs' states, both themes,
  1280 px and 380 px; setup asserts structure only (§4.1a).
- **§4.1c mutations (five-step checklist, recorded in the PR):** (M1) countermeasure check
  forced true → the "withheld" test fails; (M2) gcd taken on `s'^e − EM + 1` → factor test
  fails; (M3) Corollary 9.51 uses `gcd(x + 1, N)` only after a trivial root → factoring test
  fails; (M4) `X` and `Y` swapped → recovered-`m` test fails; (M5) oracle returns `lsb(c)`
  instead of `lsb(c^d)` → recovery test fails; (M6) query counter not incremented → counter
  claim fails. One at a time; build succeeds, bundle hash moves, a NAMED test goes red.
- **§4.1d negative claims (one per tab):**
  - Tab 7: *"Each employee's key pair is valid on its own — `e·d ≡ 1 mod φ(N)` and the round
    trip succeeds — and any one of them still decrypts every colleague's mail."* Fixture: the
    two employee keys, each passing the same identity and round-trip checks Tab 1 renders
    (all green), then card 2 reads B's message from A's pair. Verdict shape: `VALID KEY —
    AND EVERY COLLEAGUE EXPOSED`.
  - Tab 8: *"The server never returns a plaintext, only one bit, and that is enough to decrypt
    everything it can be sent."* Fixture: the oracle log shows only 0/1 responses (asserted:
    every logged response is a single bit) and the recovered plaintext re-encrypts to `y`.
- **Scope note for the page, not a claim:** the parity oracle leaks a bit of the raw RSA
  preimage for every ciphertext. Whether a padded deployment leaks that bit depends on where
  in decryption the leak occurs; the page says so and links the Bleichenbacher tab rather than
  claiming anything about OAEP or PSS.

## README and card follow-up

- README `What It Is` and `Live Demo` (`README.md:27` says "six tabbed panels" — make it
  eight); `What Can Go Wrong` gains three bullets (unchecked CRT, shared modulus, any bit-leaking
  decryption oracle). This README has no numbered `Exhibits` list; do not restructure it to add
  one — extend the existing sections.
- **Fix found while reading, verify before changing:** the CVE card "Debian weak RSA keys"
  (`index.html:~1196`) says "GCD across many public keys factored thousands of … keys". Heninger
  et al. (USENIX Security 2012) excluded Debian weak keys as *repeated* keys and reported them
  separately (their Table 2); the bug left 15 bits of entropy, so the keys were enumerable, and
  an identical modulus cannot be split by gcd. Re-read the paper and correct the card. The
  "Mining Your Ps and Qs" card calls shared-prime GCD "a direct cousin of small-exponent/CRT
  recovery" — it is not; it is an entropy failure. Point that card at Factor Forge's new
  Shared Primes tab (separate extension brief in this batch) instead.
- Catalog handoff (do not edit `../crypto-lab`): chips may gain `CRT Fault Attack`,
  `Common Modulus`, `Parity Oracle`. Update `teach/_src/worksheets/public-key/rsa-forge.md`
  only if an anchor it names moved — none should.

## Do not touch

Tabs 1–6 and their IDs, the pinned √eNFS values (`attacks.ts:28–43`), the Bleichenbacher step
order, `millerRabin`'s witness set, theme, header.

## Non-goals (each gets a one-line in-page note)

Faults against RSA-PSS (randomised encoding changes the attack; not shown here) · physical fault
injection (the bit flip is chosen in software) · Manger-style OAEP oracles · partial-key and
lattice attacks (crypto-lab-rsa-small-roots) · batch GCD over many keys (crypto-lab-factor-forge).

## Sources

- Katz & Lindell, *Introduction to Modern Cryptography*, 3rd ed., CRC Press 2021,
  ISBN 9780815354369 — §12.5.6 (CRT fault; dependent public keys I and II), Corollary 9.51
  (§9.2.5), §12.5.3 and Theorem 12.31 — checked against the book text.
- D. Boneh, R. A. DeMillo, R. J. Lipton, "On the Importance of Checking Cryptographic
  Protocols for Faults", EUROCRYPT '97, LNCS 1233, pp. 37–51, 1997.
  https://link.springer.com/chapter/10.1007/3-540-69053-0_4
- M. Joye, A. K. Lenstra, J.-J. Quisquater, "Chinese Remaindering Based Cryptosystems in the
  Presence of Faults", *Journal of Cryptology* 12(4):241–245, 1999, doi:10.1007/s001459900055
  — the single-faulty-signature `gcd(s'^e − m, N)` variant; their introduction cites
  A. K. Lenstra's September 1996 memo among earlier reports, but presents the method as
  improving Bellcore's. Credit the variant to this paper, not to the memo.
- D. Boneh, "Twenty Years of Attacks on the RSA Cryptosystem", *Notices of the AMS*
  46(2):203–213, 1999. https://crypto.stanford.edu/~dabo/pubs/abstracts/RSAattack-survey.html
- G. J. Simmons, "A 'Weak' Privacy Protocol Using the RSA Crypto Algorithm", *Cryptologia*
  7(2):180–182, 1983, doi:10.1080/0161-118391857900 (common-modulus attack).
- J. M. DeLaurentis, "A Further Weakness in the Common Modulus Protocol for the RSA
  Cryptoalgorithm", *Cryptologia* 8(3):253–259, 1984, doi:10.1080/0161-118491859060 (an insider
  with one key pair breaks the shared modulus).
- W. Alexi, B. Chor, O. Goldreich, C. P. Schnorr, "RSA and Rabin Functions: Certain Parts Are
  as Hard as the Whole", *SIAM J. Comput.* 17:194–209, 1988. https://cr.yp.to/bib/1988/alexi.bibtex
- N. Heninger, Z. Durumeric, E. Wustrow, J. A. Halderman, "Mining Your Ps and Qs: Detection of
  Widespread Weak Keys in Network Devices", 21st USENIX Security Symposium, 2012.
  https://factorable.net/paper.html
