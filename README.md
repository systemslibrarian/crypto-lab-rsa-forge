# crypto-lab-rsa-forge

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-blue?style=for-the-badge)](https://systemslibrarian.github.io/crypto-lab-rsa-forge/)
[![RSA-2048](https://img.shields.io/badge/RSA--2048-WebCrypto-navy?style=flat-square)](https://www.w3.org/TR/WebCryptoAPI/)
[![RSA-4096](https://img.shields.io/badge/RSA--4096-WebCrypto-navy?style=flat-square)](https://www.w3.org/TR/WebCryptoAPI/)
[![OAEP](https://img.shields.io/badge/OAEP-RFC%208017-teal?style=flat-square)](https://www.rfc-editor.org/rfc/rfc8017)
[![PSS](https://img.shields.io/badge/PSS-RFC%208017-teal?style=flat-square)](https://www.rfc-editor.org/rfc/rfc8017)
[![PKCS#1 v1.5](https://img.shields.io/badge/PKCS%231%20v1.5-LEGACY-orange?style=flat-square)](https://www.rfc-editor.org/rfc/rfc8017)

---

## What It Is

RSA Forge is a browser-based interactive demonstration of RSA encryption, signatures, and real attack vectors. It covers textbook RSA (raw BigInt modular exponentiation), RSA-OAEP-SHA-256 encryption (RFC 8017 §7.1), RSA-PSS-SHA-256 signatures (RFC 8017 §8.1), Håstad's broadcast attack on small-exponent unpadded RSA, and Bleichenbacher's adaptive chosen-ciphertext attack on PKCS#1 v1.5 padding oracles. RSA is an asymmetric (public-key) cryptosystem — security rests on the hardness of integer factorization. All operations run entirely in the browser using the WebCrypto API for real 2048/4096-bit keys and native JavaScript BigInt for textbook arithmetic; there is no backend.

## When to Use It

- **Encrypting data for a single recipient over an untrusted channel** — RSA-OAEP provides IND-CCA2 security, meaning ciphertexts are non-malleable and semantically secure under chosen-ciphertext attack.
- **Signing data to prove authenticity and integrity** — RSA-PSS provides a tight security reduction to the RSA problem in the random oracle model, making it the preferred RSA signature scheme for new systems.
- **Wrapping symmetric keys for hybrid encryption** — RSA-OAEP is commonly used to transport an AES session key, since RSA plaintext is limited to modulus size minus padding overhead (k − 66 bytes for SHA-256).
- **Legacy interoperability with systems that require RSA** — many existing protocols (TLS certificate signatures, S/MIME, PKCS#12) still mandate RSA support.
- **Do NOT use RSA when post-quantum security is required** — Shor's algorithm breaks all RSA key sizes in polynomial time on a fault-tolerant quantum computer. Use ML-KEM (FIPS 203) for key encapsulation or ML-DSA (FIPS 204) for signatures instead.

## Live Demo

🔗 **https://systemslibrarian.github.io/crypto-lab-rsa-forge/**

The demo has six tabbed panels. You can generate real RSA key pairs (small or 2048/4096-bit), encrypt and decrypt messages with textbook RSA or RSA-OAEP, sign and verify with RSA-PSS, run a live Håstad broadcast attack that recovers plaintext via CRT and cube root, and execute a real Bleichenbacher PKCS#1 v1.5 padding oracle attack on 128-bit RSA. Controls include key size selection (32-bit primes, 2048-bit, 4096-bit), plaintext input, and attack abort.

## What Can Go Wrong

- **Using textbook RSA without padding** — textbook RSA is deterministic: the same plaintext always produces the same ciphertext, enabling chosen-plaintext attacks and the homomorphic property (c₁·c₂ = Enc(m₁·m₂)).
- **Small public exponent without OAEP** — with e=3 and no padding, intercepting the same message sent to three recipients allows immediate recovery via the Chinese Remainder Theorem and integer cube root (Håstad 1988).
- **PKCS#1 v1.5 encryption padding oracle** — any system that distinguishes PKCS#1 v1.5 padding errors from other decryption errors leaks a one-bit oracle, enabling Bleichenbacher's adaptive chosen-ciphertext attack to recover the full plaintext (Bleichenbacher 1998). The ROBOT attack (2017) found 8 major TLS implementations still vulnerable 19 years later.
- **Insufficient key size** — RSA-1024 is considered factored-equivalent in capability for well-funded adversaries. NIST SP 800-57 requires 2048-bit minimum; 3072-bit or larger for data protected beyond 2030.
- **No forward secrecy in RSA key exchange** — TLS 1.3 removed RSA key exchange entirely because compromise of the server's long-term RSA private key retroactively decrypts all past sessions. Use ephemeral ECDHE instead.

## Real-World Usage

- **TLS certificates** — the majority of HTTPS certificates on the public internet use RSA-2048 or RSA-4096 keys for the certificate's public key, with signatures using RSASSA-PKCS1-v1_5 or RSASSA-PSS.
- **SSH authentication** — OpenSSH uses RSA key pairs (typically 3072-bit or 4096-bit) for client and host authentication, with `rsa-sha2-256` and `rsa-sha2-512` signature algorithms.
- **S/MIME email encryption** — RFC 8551 uses RSA-OAEP to wrap per-message content-encryption keys, providing end-to-end encrypted email in enterprise environments.
- **Code signing** — Windows Authenticode, macOS codesign, and Java JAR signing all support RSA signatures to verify that binaries have not been tampered with.
- **JSON Web Tokens (JWT)** — the `RS256`, `RS384`, and `RS512` algorithms in RFC 7518 use RSASSA-PKCS1-v1_5 signatures; `PS256`, `PS384`, `PS512` use RSASSA-PSS.

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

## Related Demos

- **[crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/)** — ML-KEM-768 (FIPS 203): the RSA replacement
- **[crypto-lab-iron-letter](https://systemslibrarian.github.io/crypto-lab-iron-letter/)** — AES-GCM and ChaCha20-Poly1305 symmetric encryption
- **[crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/)** — ML-DSA-65 (FIPS 204): post-quantum digital signatures
- **[crypto-compare](https://systemslibrarian.github.io/crypto-compare/#asymmetric)** — Side-by-side algorithm comparison
- **[Crypto Lab](https://systemslibrarian.github.io/)** — Full collection of interactive cryptography demos

---

> *"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
