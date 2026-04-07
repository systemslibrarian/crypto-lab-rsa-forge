# crypto-lab-rsa-forge

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-blue?style=for-the-badge)](https://systemslibrarian.github.io/crypto-lab-rsa-forge/)
[![RSA-2048](https://img.shields.io/badge/RSA--2048-WebCrypto-navy?style=flat-square)](https://www.w3.org/TR/WebCryptoAPI/)
[![RSA-4096](https://img.shields.io/badge/RSA--4096-WebCrypto-navy?style=flat-square)](https://www.w3.org/TR/WebCryptoAPI/)
[![OAEP](https://img.shields.io/badge/OAEP-RFC%208017-teal?style=flat-square)](https://www.rfc-editor.org/rfc/rfc8017)
[![PSS](https://img.shields.io/badge/PSS-RFC%208017-teal?style=flat-square)](https://www.rfc-editor.org/rfc/rfc8017)
[![PKCS#1 v1.5](https://img.shields.io/badge/PKCS%231%20v1.5-LEGACY-orange?style=flat-square)](https://www.rfc-editor.org/rfc/rfc8017)

🔗 **Live demo:** https://systemslibrarian.github.io/crypto-lab-rsa-forge/

Browser-based interactive demonstration of RSA — covering textbook RSA, OAEP padding, PSS signatures,
and live attack demonstrations including Håstad's broadcast attack and Bleichenbacher's PKCS#1 v1.5 oracle.
All operations run entirely in your browser using real cryptographic arithmetic — no backends, no simulated math.

---

## Overview

RSA remains one of the most widely deployed cryptographic algorithms in 2026 — TLS certificates, SSH keys,
JWT signing, code signing, and S/MIME email all rely on RSA. Yet real-world deployments still fail in
predictable ways: wrong padding choices, small exponents without proper padding, and legacy PKCS#1 v1.5
encryption left in production long after safer alternatives exist.

This demo covers the full arc from textbook RSA through to post-quantum migration context, giving engineers
an interactive understanding of why each failure mode exists and how it is exploited.

---

## Attacks Covered

### Håstad Broadcast Attack (Panel 4)
- Same unpadded message sent to 3 recipients with e=3
- Real CRT reconstruction of m³ using BigInt arithmetic
- Real integer cube root recovery of m via Newton's method
- Demonstrates why OAEP randomization is non-negotiable
- **Refs:** Håstad (1988); Coppersmith (1997)

### Bleichenbacher PKCS#1 v1.5 Padding Oracle (Panel 5)
- Real PKCS#1 v1.5 padding conformance oracle on small (128-bit) RSA
- Adaptive chosen-ciphertext queries demonstrating interval narrowing
- Animated convergence of [a, b] intervals toward the plaintext
- Explains why TLS 1.3 removed RSA key exchange entirely
- **Ref:** Bleichenbacher (1998), "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1." CRYPTO '98.

---

## Primitives Used

| Primitive | Where | Status |
|-----------|-------|--------|
| Textbook RSA | Panel 1 | ⛔ Never use directly |
| RSA-OAEP-SHA-256 | Panel 2 | ✅ Recommended |
| RSA-PSS-SHA-256 | Panel 3 | ✅ Recommended |
| PKCS#1 v1.5 encryption | Panel 5 | ⛔ Avoid |
| BigInt CRT + cube root | Panel 4 | Demo only |

**WebCrypto:** RSA-OAEP and RSA-PSS use the browser's native `crypto.subtle` API with real 2048/4096-bit keys.

**BigInt arithmetic:** Textbook RSA, key parameter visualization, Håstad attack, and Bleichenbacher attack use native JavaScript `BigInt` — real modular exponentiation with real primes, no simulation.

---

## Running Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-rsa-forge.git
cd crypto-lab-rsa-forge
npm install
npm run dev
```

Open http://localhost:5173/crypto-lab-rsa-forge/ in your browser.

### Build for production

```bash
npm run build
```

Output is in `dist/`.

### Deploy to GitHub Pages

```bash
npm run deploy
```

Requires `gh-pages` package and appropriate GitHub repository permissions.

---

## Security Notes

**RSA-OAEP is safe.** RSA-PSS is safe. These are the primitives you should use for new systems.

**Textbook RSA is not safe** for real data. It is deterministic — the same plaintext always produces the same ciphertext, enabling trivial chosen-plaintext attacks. Use RSA-OAEP for encryption.

**PKCS#1 v1.5 encryption is not safe** in most deployment contexts. Bleichenbacher's 1998 attack exploits a padding oracle exposed by any system that distinguishes padding errors from other errors. The ROBOT attack (2017) found 8 major production TLS stacks still vulnerable 19 years later. Use RSA-OAEP.

**PKCS#1 v1.5 signatures** (RSASSA-PKCS1-v1_5) are not the same as PKCS#1 v1.5 encryption. Signature PKCS#1 v1.5 is still widely used and considered acceptable; RSA-PSS is preferred for new systems.

**Small e without padding** is catastrophic. With e=3 and no padding, interception of the same message sent to three recipients allows immediate recovery via CRT and cube root. Always use OAEP.

**Key sizes:** Follow NIST SP 800-57 — 2048-bit minimum, 3072+ for long-term security. RSA-4096 provides ~140-bit classical security but still breaks under Shor's algorithm.

---

## Accessibility

This demo targets WCAG 2.1 AA compliance:

- **Keyboard navigation** throughout — all panels, buttons, and form inputs are keyboard accessible
- **ARIA roles and labels** on all interactive elements including tablist/tabpanel structure
- **Focus indicators** visible in both dark and light modes (minimum 3:1 contrast ratio)
- **Screen reader support** — ARIA live regions announce cryptographic operation results, attack progress, and error states
- **Color-code redundancy** — all security status indicators (safe/warn/danger) include text labels, never color alone
- **Reduced motion** — all animations respect `prefers-reduced-motion: reduce`
- **Mobile-first** — base styles target 320px viewport; all tap targets minimum 44×44px; no horizontal scrolling
- **Minimum font size** — nothing smaller than 12px used for decorative elements; body text 16px; functional text minimum 14px
- **Contrast ratios** — all text meets 4.5:1 (normal) or 3:1 (large) in both dark and light modes

---

## Why This Matters

RSA is in millions of systems. Understanding its failure modes is essential for any engineer
involved in the post-quantum migration (FIPS 203/204/205, NIST PQC). The mistakes are still being
made in production: wrong padding, PKCS#1 v1.5 left enabled, no padded small-exponent enforcement.

This demo gives you direct, interactive experience with both the secure and insecure paths.

---

## Related Demos

- **[crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/)** — ML-KEM-768 (FIPS 203): the RSA replacement
- **[crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/)** — AES-GCM and ChaCha20-Poly1305 symmetric encryption
- **[crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/)** — ML-DSA-65 (FIPS 204): post-quantum digital signatures
- **[crypto-compare](https://systemslibrarian.github.io/crypto-compare/#asymmetric)** — Side-by-side algorithm comparison
- **[Crypto Lab](https://systemslibrarian.github.io/)** — Full collection of interactive cryptography demos

---

## Stack

- **Vite** + **TypeScript** (ES2022 target)
- **Vanilla CSS** — no Tailwind, no frameworks
- **WebCrypto API** — RSA-OAEP and RSA-PSS with real browser key material
- **Native BigInt** — textbook RSA, Håstad attack, Bleichenbacher attack — real arithmetic

---

> "So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31
