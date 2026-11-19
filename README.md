# crypto-lab-rsa-forge

## What It Is

RSA Forge is a browser-based interactive demonstration of RSA encryption, signatures, and real attack vectors. It opens with a plain-language, no-math on-ramp — a padlock analogy for public/private keys and the trapdoor nature of RSA — so a newcomer meeting RSA for the first time has a mental model before any parameter appears, while inline "?" glossary tooltips (φ(n), modular exponentiation, MGF1, CRT, semantic security / IND-CCA2, homomorphic) define jargon just-in-time without dumbing down the underlying math. It then covers textbook RSA (raw BigInt modular exponentiation), RSA-OAEP-SHA-256 encryption (RFC 8017 §7.1), RSA-PSS-SHA-256 signatures (RFC 8017 §8.1), Håstad's broadcast attack on small-exponent unpadded RSA, Bleichenbacher's adaptive chosen-ciphertext attack on PKCS#1 v1.5 padding oracles, and the 2026 delayed-target RSA / √eNFS attack from ePrint 2026/2131, which forges e-th roots with temporary raw-RSA oracle access without factoring N or recovering the private key. A "factoring wall" lets you brute-force a real tiny modulus in milliseconds and contrasts it with the age-of-the-universe cost of factoring a 2048-bit key, making the trapdoor tangible; the Bleichenbacher panel demonstrates RSA's multiplicative homomorphism (Enc(a)·Enc(b) = Enc(a·b)) on the live key before the interval search, so the attack reads as consequence rather than magic. RSA security is not solely "factoring" in every model — the paper's result is a narrower oracle-assisted forgery setting, distinct from the ordinary factoring problem. All operations run entirely in the browser using the WebCrypto API for real 2048/4096-bit keys and native JavaScript BigInt for textbook arithmetic; there is no backend.

Two appended tabs add implementation pitfalls and a one-bit decryption oracle. **Implementation Pitfalls** factors a real WebCrypto RSA-2048 key from a software-simulated CRT fault, shows how one employee's private pair breaks a shared modulus, and contrasts the public common-modulus attack with independently randomized OAEP encodings. **Parity Oracle** recovers the raw RSA preimage from only 0/1 answers, revealing bytes from right to left and checking the result by re-encryption. Verify-before-release is enabled on arrival; exposing faults is an explicit broken mode. **Fault the Verifier** faults the modulus a *verifier* holds, Seifert's attack: it takes a real RSA-512 key, faults one byte of its modulus until the faulted N̂ is prime or splits into small primes, builds a private exponent for N̂ with no factoring of the real key, and forges a signature the faulted verifier accepts and an honest one rejects — then reproduces, in the browser, the two facts Muir states about the real 2048-bit Xbox modulus (§4.3).

## Verification & Claim Manifest

- **2026 delayed-target RSA / √eNFS:** Shea, Haller, Suhl, Heninger, Thomé. *Forging 1024-bit RSA signatures in nearly SNFS time*. IACR ePrint 2026/2131. Sections cited on the page: §1, §2, Fig. 6, §3.1, Fig. 3, Fig. 4, §4, §4.5, §5, Fig. 7, §6, §7, and §7.3. The paper is a temporary raw-RSA oracle attack (DT-RSA) and is distinct from plain RSA, ordinary factoring, and OM-RSA; it does not solve efficient one-more RSA or recover the primes/private key.
- **Live verification:** the browser uses the exact §4 public key and target values from the paper’s HSM example (e = 65537, N, t, and s = t^(1/e) mod N). The button computes s^65537 mod N and verifies equality to t. This is a check of the published values and the equation itself; it does not rerun the paper’s number-field sieve computation or establish how the authors derived s.
- **Security context:** Fig. 7 gives the paper’s extrapolated complexity estimates: GNFS vs √eNFS and the raw-oracle query counts. The paper’s caveat is explicit: the estimates are extrapolated and upper-bounded (§6).
- **Is this a factoring breakthrough?** No — §4.5 says the 1024-bit key was generated outside the HSM and imported; the attack used black-box HSM oracle responses and never required the factors or private key. The paper deliberately separates DT-RSA from ordinary factoring and OM-RSA.

## When to Use It

- **Encrypting data for a single recipient over an untrusted channel** — RSA-OAEP provides IND-CCA2 security, meaning ciphertexts are non-malleable and semantically secure under chosen-ciphertext attack.
- **Signing data to prove authenticity and integrity** — RSA-PSS provides a tight security reduction to the RSA problem in the random oracle model, making it the preferred RSA signature scheme for new systems.
- **Wrapping symmetric keys for hybrid encryption** — RSA-OAEP is commonly used to transport an AES session key, since RSA plaintext is limited to modulus size minus padding overhead (k − 66 bytes for SHA-256).
- **Legacy interoperability with systems that require RSA** — many existing protocols (TLS certificate signatures, S/MIME, PKCS#12) still mandate RSA support.
- **Do NOT use RSA when post-quantum security is required** — Shor's algorithm breaks all RSA key sizes in polynomial time on a fault-tolerant quantum computer. Use ML-KEM (FIPS 203) for key encapsulation or ML-DSA (FIPS 204) for signatures instead.
- Do NOT treat this as production cryptography — it is a teaching demo for understanding RSA and its attacks, not a hardened library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-rsa-forge](https://systemslibrarian.github.io/crypto-lab-rsa-forge/)**

Above the nine tabbed panels sits a plain-language intro card (padlock analogy + trapdoor) that frames public-key crypto before any math. Inside the panels you can generate real RSA key pairs (small or 2048/4096-bit), feel the factoring trapdoor by brute-forcing a tiny real modulus in the Textbook panel's factoring wall, encrypt and decrypt messages with textbook RSA or RSA-OAEP, watch OAEP's avalanche effect at a high level before expanding the full byte-field structure, sign and verify with RSA-PSS, run a live Håstad broadcast attack that recovers plaintext via CRT and cube root, and execute a real Bleichenbacher PKCS#1 v1.5 padding oracle attack on 128-bit RSA (including a "You Are the Oracle" step-through and a homomorphism demo). Each completed attack closes with a plain-language "what just happened" summary tied to the numbers on screen. Controls include key size selection (32-bit primes, 2048-bit, 4096-bit), plaintext input, and attack abort.

The two new tabs add Generate → Sign → Inject → Factor, a shared-modulus employee scenario, an OAEP contrast, and a parity attack with single-step, progress, Cancel and resume. The parity demo defaults to 512-bit teaching keys and also runs the full attack on fresh 2048-bit keys.

## What Can Go Wrong

- **Releasing unchecked CRT signatures** — one faulty CRT half can reveal a prime through a gcd. Verify the result before releasing it; the fault here is deliberately injected in the local BigInt signer, not in WebCrypto.
- **Sharing a modulus between users** — possession of one private pair lets an insider factor the modulus and derive colleagues' keys. A public observer can also recover an identical raw message encrypted under coprime exponents; independently randomized OAEP encodings prevent that specific recipe, but reusing one encoding does not.
- **Returning even one bit from decryption** — the parity oracle returns only the raw preimage's least-significant bit, yet exactly `bitLength(N)` adaptive queries recover the entire preimage. This does not assert that OAEP or PSS deployments expose that raw-RSA bit.
- **Faulting the modulus a verifier holds** — RSA signature verification is only as trustworthy as the modulus the verifier reads. Flip a few bits of N into a prime or easily-factored N̂ and an attacker can forge a private exponent for N̂ and sign anything the faulted device accepts — no factoring of the real key (Seifert's attack; J. A. Muir, *Seifert's RSA Fault Attack: Simplified Analysis and Generalizations*, 2005). Protect the stored modulus and verify under a modulus whose integrity is checked.

- **Using textbook RSA without padding** — textbook RSA is deterministic: the same plaintext always produces the same ciphertext, enabling chosen-plaintext attacks and the homomorphic property (c₁·c₂ = Enc(m₁·m₂)).
- **Small public exponent without OAEP** — with e=3 and no padding, intercepting the same message sent to three recipients allows immediate recovery via the Chinese Remainder Theorem and integer cube root (Håstad 1988).
- **PKCS#1 v1.5 encryption padding oracle** — any system that distinguishes PKCS#1 v1.5 padding errors from other decryption errors leaks a one-bit oracle, enabling Bleichenbacher's adaptive chosen-ciphertext attack to recover the full plaintext (Bleichenbacher 1998). The ROBOT attack (2017) reported vulnerable products from at least eight vendors and open source projects 19 years later; the robotattack.org disclosure table has since grown to 21 affected vendors and products.
- **Reverse-Bleichenbacher research (October 2026)** — [Lü et al., ePrint 2026/2414](https://eprint.iacr.org/2026/2414), received 8 October and approved 11 October 2026; the record lists NDSS 2027 (minor revision). Their variant recovers low-order secret bytes first and terminates once the target secret is recovered, with reported 2048-bit experiments against a standards-conforming PKCS#1 v1.5 oracle in legacy TLS RSA key exchange. This is conditional on an exploitable decryption oracle, not a general factoring result or a break of OAEP, PSS, or TLS 1.3 key exchange. The visible research card in the Bleichenbacher panel distinguishes it from this lab’s classical full-plaintext attack on 128-bit RSA with a leading-`00 02` oracle; the browser does not implement the new variant or reproduce its benchmarks. Deployment guidance: disable legacy TLS RSA key exchange and eliminate PKCS#1 v1.5 decryption-oracle leakage.
- **Insufficient key size** — RSA-1024 is considered factored-equivalent in capability for well-funded adversaries. [NIST SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) rates 2048-bit RSA at 112 bits of classical security strength and 3072-bit at 128 bits (Table 2), and its Table 4 had allowed 112-bit strength for applying protection only through 2030. [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final) (final report, published 27 October 2026) replaces that projected 2031 cut-off: quantum-vulnerable public-key algorithms — RSA at any key size — are deprecated after 2030 and disallowed under NIST standards and guidelines after 2035, so a larger modulus does not extend the schedule.
- **No forward secrecy in RSA key exchange** — TLS 1.3 removed RSA key exchange entirely because compromise of the server's long-term RSA private key retroactively decrypts all past sessions. Use ephemeral ECDHE instead.

## Real-World Usage

- **TLS certificates** — RSA was still the most common public-key type in certificates logged to Certificate Transparency when Cloudflare launched its [Radar CT dashboard](https://radar.cloudflare.com/certificate-transparency) ([Cloudflare blog, 26 September 2025](https://blog.cloudflare.com/new-regional-internet-traffic-and-certificate-transparency-insights-on-radar/): more than 65% RSA, the remainder ECDSA, with ECDSA "increasingly adopted"); check the live dashboard for the current split. RSA signatures on certificates use RSASSA-PKCS1-v1_5 or RSASSA-PSS.
- **SSH authentication** — OpenSSH uses RSA key pairs (typically 3072-bit or 4096-bit) for client and host authentication, with `rsa-sha2-256` and `rsa-sha2-512` signature algorithms.
- **S/MIME email encryption** — [RFC 8551 §2.3](https://www.rfc-editor.org/rfc/rfc8551.html#section-2.3) (S/MIME 4.0) keeps PKCS #1 v1.5 RSA key transport at MUST- (still required, but expected to lose MUST status) and RSAES-OAEP at SHOULD+ (expected to be promoted to MUST), with ECDH ephemeral-static for P-256 and X25519 as the unqualified MUSTs ([§1.3](https://www.rfc-editor.org/rfc/rfc8551.html#section-1.3) defines the MUST-/SHOULD+ levels). Either RSA scheme encrypts the per-message content-encryption key, providing end-to-end encrypted email in enterprise environments.
- **Code signing** — Windows Authenticode, macOS codesign, and Java JAR signing all support RSA signatures to verify that binaries have not been tampered with.
- **JSON Web Tokens (JWT)** — the `RS256`, `RS384`, and `RS512` algorithms in RFC 7518 use RSASSA-PKCS1-v1_5 signatures; `PS256`, `PS384`, `PS512` use RSASSA-PSS.

**Standards reviewed 15 November 2026:** the certificate key-type share above is Cloudflare's published September 2025 figure, not a 2026 number — the live Radar dashboard is the current source; S/MIME requirement levels are quoted from RFC 8551 §1.3 and §2.3; RSA key-size guidance now pairs SP 800-57 Part 1 Rev. 5 (Tables 2 and 4) with the final NIST IR 8547 transition schedule (§4.1).

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-rsa-forge
cd crypto-lab-rsa-forge
npm install
npm run dev
```

## Related Demos

- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203), the post-quantum key encapsulation built to replace RSA key transport.
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA (FIPS 204), the post-quantum replacement for RSA/ECDSA signatures.
- [crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/) — hybrid public-key encryption (ECIES, RSA-OAEP, AES-256-GCM) for real message sealing.
- [crypto-lab-ecdsa-forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — elliptic-curve signatures and the nonce-reuse attacks that break them.
- [crypto-lab-shor](https://systemslibrarian.github.io/crypto-lab-shor/) — Shor's algorithm, the quantum period-finding attack that factors RSA moduli.
- [crypto-lab-factor-forge](https://systemslibrarian.github.io/crypto-lab-factor-forge/) — why breaking RSA is not the same as factoring N, and why a secure trapdoor does not mean a broken modulus is “solved.”
- [crypto-lab-privacy-pass](https://systemslibrarian.github.io/crypto-lab-privacy-pass/) — RSA blind signatures, Privacy Pass, and the one-more / delayed-target assumptions covered in the 2026 √eNFS attack.

## Extension verification

`npm test` covers fresh WebCrypto fault signatures, both fault halves, fifty randomized private-pair factorizations, independent OAEP decoding, and an independently implemented interval-doubling parity recovery. Browser claim tests independently recompute public gcd/Bezout equations, compare recovered factors with the exported JWK, check both negative fixtures, and finish a real 2048-bit parity run after cancellation and resumption. Accessibility tests exercise old and new states at desktop and phone widths, plus the appended tabs at 320px.

`npm run test:mutations` builds ten concrete source mutations individually, checks the exact served JavaScript, requires a named assertion failure with zero retries, and restores the source and original bundle bytes before re-running the owning test. The checked-in `mutation-evidence.json` records the source diffs and outcomes; `extension-handoff.md` records scope and verification.

## Building and Deploying

```bash
npm run build      # production build, output in dist/
npm run deploy     # request the existing gated Pages workflow on main (authenticated gh required)
```

After `npm run dev`, open http://localhost:5173/crypto-lab-rsa-forge/ in your browser.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
