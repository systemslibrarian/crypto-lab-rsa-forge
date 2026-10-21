# RSA Forge — Implementation Pitfalls and Parity Oracle

Starting main: `925498c1f145db6ab3fb726da1cdaf47fb949887`.
Brief: `brief-extension.md`.
Live: https://systemslibrarian.github.io/crypto-lab-rsa-forge/

Tabs 7 and 8 are appended without renumbering the six original tabs. Tab 7
uses a real WebCrypto RSA-2048 key to contrast a verified signature, an
explicitly simulated CRT fault, the default verify-before-release protection,
and two independently checked gcd routes to its private factors. It also
factors a shared modulus from one employee's private pair and demonstrates
the public Bezout attack on identical raw messages, with a fresh-OAEP contrast.
Tab 8 uses the book's halving parity attack, not the doubling attack, and
reveals low bytes first. The oracle closure alone holds the private key.
The 2048-bit path uses CRT, supports cancellation/resumption, and never labels
a partial recovery as plaintext. Every full recovery must re-encrypt to the
original ciphertext.

## Verification

- 54 unit tests passed, including eight new tests. Fresh WebCrypto keys cover
  both CRT halves and low/middle/high fault bits. Fifty randomized key-pair
  factorizations, noninvertible common-modulus inputs, independently randomized
  OAEP, five 512-bit parity runs, one full 2048-bit run, and a separately
  implemented interval-doubling recovery are exercised. Original witness sets
  and pinned paper values are unchanged.
- All 32 browser claim tests passed. The seven new claims independently check
  public arithmetic, intercept the actual exported JWK to compare factors,
  decode OAEP with Node SHA-256, assert bit-only oracle logs and exact query
  counts, and finish a 2048-bit attack after cancelling and resuming it.
- All three accessibility walks passed: original and new states at desktop
  and 380px, plus both new tabs at 320px. Scoped link contrast, semantic region
  roles, wrapping of long parity integers, and the old always-visible paper
  grid's fixed minimum width were repaired. No exemption was added.
- Ten concrete mutations were killed: bypass the release check, alter the
  fault difference, accept only a trivial square root, swap Bezout powers,
  return ciphertext parity, stop counting queries, remove either negative
  sentence, and break each negative fixture's positive prerequisite.
  `mutation-evidence.json` contains source diffs, successful builds, changed
  hashes, named failures, exact restoration and green owning tests. The
  runner serves its prebuilt bundle, checks the page's loaded module names
  and fetched bytes, and asserts restoration again after the owning test.
  Every mutation test runs with zero retries.
- The shared-modulus fixture visibly passes both employees' identity and
  round-trip checks before reading B's mail from A's pair. The parity fixture
  logs only 0/1 and verifies the recovered value by re-encryption. Both
  compromises use alarm styling and explicit text, never a success palette.
- Desktop, mobile, grayscale and deuteranopia states were inspected. Local
  browser checks used Chromium 153.0.8010.0 because the pinned download
  returned a non-ZIP response; the executable override is ignored by git.
  CI retains the original pinned browser and normal build-before-preview gate.

The Debian card is corrected against Heninger et al.'s 2012 paper: Debian's
15-bit entropy defect made keys enumerable; repeated moduli do not split by
gcd. The separate shared-prime incident is an entropy failure and links to
Factor Forge. The single-fault route credits Joye, Lenstra and Quisquater
(1999); the correct-plus-faulty route credits Boneh, DeMillo and Lipton (1997).
Physical faults, RSA-PSS faults, Manger oracles, lattice attacks and batch GCD
remain explicitly outside this exhibit. No original worksheet anchor moved.

## Catalog handoff — no shared edits

Suggested sentence: “Factor a real RSA key from one simulated CRT fault,
expose colleagues sharing a modulus, then recover a plaintext from one-bit
parity answers.”
Suggested chips: `CRT Fault Attack`, `Common Modulus`, `Parity Oracle`.
Concept deepened: **7. Factoring** (implementation failures and RSA assumptions).
Related demos: Factor Forge and RSA Small Roots.
Call sites: `src/pitfalls.ts`, `src/parity.ts`, `src/jwk.ts`,
`src/extension-panels.ts`, `src/pitfalls-panel.ts`, `src/parity-panel.ts`.
The byte-grid renderer in `src/attacks.ts` gained an optional prefix/low-bit
mode; its default Bleichenbacher behavior is unchanged.

Header, theme, footer, existing crypto behavior and deployment workflow remain
intact. The shared catalog, counsel, census and checker are unchanged. The
fleet-wide sync result is not re-certified because unrelated checkouts are
unavailable. The final published SHA and live-byte proof accompany delivery.
